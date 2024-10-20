package client

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"

	"github.com/diegommm/technicolor-cga4233tch3/pkg/httpdoer"
)

const (
	DefaultBaseURL   = "https://192.168.0.1"
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
	defaultUsername = "custadmin"
	defaultPassword = "cga4233"
)

// custadmincustadmin
// Cga42331

type Client interface {
	Login(context.Context) error
	Logout(context.Context) error
	SetAuth(ctx context.Context, user, pass string) error
}

type Params struct {
	httpdoer.HTTPDoer
	BaseURL                          string
	UserAgent                        string
	Username, Password               string
	DefaultUsername, DefaultPassword string
	TryDefaultAuthFirst              bool
	SetAuthIfDefault                 bool
	TLSVerify                        bool
}

func (p Params) WithDefaults() Params {
	if p.HTTPDoer == nil {
		p.HTTPDoer = httpdoer.New(!p.TLSVerify)
	}
	p.BaseURL = cmp.Or(p.BaseURL, DefaultBaseURL)
	p.UserAgent = cmp.Or(p.UserAgent, DefaultUserAgent)
	p.Username = cmp.Or(p.Username, defaultUsername)
	p.Password = cmp.Or(p.Password, defaultPassword)
	p.DefaultUsername = cmp.Or(p.DefaultUsername, defaultUsername)
	p.DefaultPassword = cmp.Or(p.DefaultPassword, defaultPassword)
	//p. = util.Or(p., Default)

	if p.Username == p.DefaultUsername && p.Password == p.DefaultPassword {
		p.TryDefaultAuthFirst = false
		p.SetAuthIfDefault = false
	}

	return p
}

func New(p Params) (Client, error) {
	p = p.WithDefaults()

	p.HTTPDoer = httpdoer.SetHeaders(p.HTTPDoer, httpdoer.KeyValue{
		httpdoer.HeaderNameUserAgent:   p.UserAgent,
		httpdoer.HeaderNameContentType: httpdoer.ContentTypeFormURLEncoded,
	}.ToHTTPHeader())
	p.HTTPDoer = httpdoer.RemoveContentTypeIfNoBody(p.HTTPDoer)
	p.HTTPDoer = httpdoer.BufferAndCloseBody(p.HTTPDoer)
	cj, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	p.HTTPDoer = httpdoer.WithCookieJar(p.HTTPDoer, cj)

	//debug
	origDoer := p.HTTPDoer
	p.HTTPDoer = httpdoer.HTTPDoerFunc(func(req *http.Request) (*http.Response, error) {
		fmt.Printf("> %v %v\n", req.Method, req.URL)
		return origDoer.Do(req)
	})

	return &client{
		Params: p,
		cj:     cj,
	}, nil
}

type client struct {
	Params
	cj http.CookieJar

	loginResponseMu sync.RWMutex
	loginResponse   *loginResponse
}

func (c *client) storeLoginResponse(res *loginResponse) error {
	if !c.loginResponseMu.TryLock() {
		return errors.New("could not acquire lock to store login response")
	}
	defer c.loginResponseMu.Unlock()
	c.loginResponse = res
	return nil
}

func (c *client) loadLoginResponse() (*loginResponse, error) {
	if !c.loginResponseMu.TryRLock() {
		return nil, errors.New("could not acquire lock to load login response")
	}
	defer c.loginResponseMu.RUnlock()
	return c.loginResponse, nil
}

func (c *client) doAndDecode(
	ctx context.Context,
	method string,
	endpoint string,
	body io.Reader,
	resPtr any,
) ([]byte, error) {
	// build request
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	// do request
	res, err := c.HTTPDoer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perform request: %w", err)
	}
	resBytes := res.Body.(httpdoer.ReadNopCloser).Reader.(*bytes.Buffer).Bytes()

	if resPtr != nil {
		// decode response
		if err := json.Unmarshal(resBytes, &resPtr); err != nil {
			return nil, fmt.Errorf("decode JSON body: %w; raw response: %s",
				err, resBytes)
		}

		// validate response
		v, _ := resPtr.(interface{ Validate() error })
		if err := v.Validate(); err != nil {
			return nil, fmt.Errorf("validate response: %v", err)
		}
	}

	return resBytes, nil
}

func (c *client) callLogin(ctx context.Context, user, pass string) (*loginResponse, error) {
	// build request
	body := strings.NewReader(httpdoer.KeyValue{
		"username": user,
		"password": pass,
	}.ToURLValues().Encode())

	// do an decode
	var res loginResponse
	_, err := c.doAndDecode(ctx, http.MethodPost,
		"/api/v1/session/login", body, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

func (c *client) login(ctx context.Context, user, pass string) error {
	res, err := c.callLogin(ctx, user, "seeksalthash")
	if err != nil {
		return fmt.Errorf("calling login to seek salt hash: %w", err)
	}
	pass = DefaultDerivePasswordWebUI([]byte(pass), res.Salt,
		res.SaltWebUI)
	res2, err := c.callLogin(ctx, user, pass)
	if err != nil {
		return err
	}
	res2.Salt = res.Salt
	res2.SaltWebUI = res.SaltWebUI

	return c.storeLoginResponse(res)
}

func (c *client) Logout(ctx context.Context) error {
	_, err := c.doAndDecode(ctx, http.MethodPost, "/api/v1/session/logout", nil,
		nil)
	if err != nil {
		return err
	}
	return c.storeLoginResponse(nil)
}

func (c *client) callSetAuth(
	ctx context.Context,
	newUser string,
	newPass string,
	oldPass string,
	loginSalt []byte,
) error {
	// build request
	body, err := defaultNewPasswordChangeRequestBody(newUser, oldPass, newPass,
		loginSalt)
	if err != nil {
		return fmt.Errorf("generate password change body: %w", err)
	}

	// do an decode
	var res loginResponse
	_, err = c.doAndDecode(ctx, http.MethodPost, "/api/v1/changepassword",
		strings.NewReader(body), &res)
	if err != nil {
		return fmt.Errorf("call change password: %w", err)
	}

	return nil
}

func (c *client) SetAuth(ctx context.Context, user, pass string) error {
	if err := c.login(ctx, c.Username, c.Password); err != nil {
		return err
	}

	loginRes, err := c.loadLoginResponse()
	if err != nil {
		return err
	}

	err = c.callSetAuth(ctx, user, pass, c.Password, loginRes.Salt)
	if err != nil {
		return err
	}
	c.Username = user
	c.Password = pass

	return nil
}

func (c *client) Login(ctx context.Context) error {
	if c.TryDefaultAuthFirst {
		err := c.login(ctx, c.DefaultUsername, c.DefaultPassword)
		if err == nil {
			if !c.SetAuthIfDefault {
				return nil
			}
			if err := c.SetAuth(ctx, c.Username, c.Password); err != nil {
				return fmt.Errorf("setting auth after default login: %w", err)
			}
			if err := c.Logout(ctx); err != nil {
				return fmt.Errorf("logging out after default login: %w", err)
			}
		}
	}
	return c.login(ctx, c.Username, c.Password)
}
