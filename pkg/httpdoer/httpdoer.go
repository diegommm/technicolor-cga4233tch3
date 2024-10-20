package httpdoer

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/diegommm/technicolor-cga4233tch3/pkg/util"
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func New(allowInsecure bool) HTTPDoer {
	d := new(http.Client)
	if allowInsecure {
		t := http.DefaultTransport.(*http.Transport)
		t.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
		/*
			t := *http.DefaultTransport.(*http.Transport)
			t.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
			d.Transport = &t
		*/
	}

	return d
}

type HTTPDoerFunc func(*http.Request) (*http.Response, error)

func (f HTTPDoerFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func SetHeaders(d HTTPDoer, h http.Header) HTTPDoer {
	if len(h) == 0 {
		return d
	}
	return HTTPDoerFunc(func(req *http.Request) (*http.Response, error) {
		for name, values := range h {
			req.Header[name] = values
		}
		return d.Do(req)
	})
}

func RemoveContentTypeIfNoBody(d HTTPDoer) HTTPDoer {
	return HTTPDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.Body == nil {
			req.Header.Del(HeaderNameContentType)
		}
		return d.Do(req)
	})
}

type ReadNopCloser struct {
	io.Reader
}

func (rc ReadNopCloser) Close() error { return nil }

func BufferAndCloseBody(d HTTPDoer) HTTPDoer {
	return HTTPDoerFunc(func(req *http.Request) (*http.Response, error) {
		res, err := d.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(res.Body); err != nil {
			return nil, fmt.Errorf("buffering body: %w", err)
		}
		if err := res.Body.Close(); err != nil {
			return nil, fmt.Errorf("closing body: %w", err)
		}
		res.Body = ReadNopCloser{buf}
		return res, nil
	})
}

func WithCookieJar(d HTTPDoer, cj http.CookieJar) HTTPDoer {
	return HTTPDoerFunc(func(req *http.Request) (*http.Response, error) {
		for _, cookie := range cj.Cookies(req.URL) {
			req.AddCookie(cookie)
		}
		res, err := d.Do(req)
		if err != nil {
			return nil, err
		}
		if cookies := res.Cookies(); len(cookies) > 0 {
			cj.SetCookies(req.URL, cookies)
		}
		return res, nil
	})
}

func Debug(d HTTPDoer, w io.Writer) HTTPDoer {
	pool := util.NewBytesBufferAdaptivePool(2)
	sep := strings.Repeat("=", 80)

	return HTTPDoerFunc(func(req *http.Request) (*http.Response, error) {
		buf := pool.Acquire()
		defer pool.Release(buf)

		id := uuid.New().String()
		fmt.FPrintln(sep)
		fmt.FPrintln()

		req2 := req.Clone(req.Context())

		fmt.Printf("%v %v meta:%#v", req.Method, req.URL.String(), util.GetContextMeta())
		res, err := d.Do(req)
	})
}
