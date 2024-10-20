package client

import (
	"encoding/binary"
	"encoding/json"
	"net/url"
	"testing"
)

func sjclWordsToBytes(src []int32) []byte {
	// broken but works for curated tests

	ret := make([]byte, 0, 4*len(src))
	for _, v := range src {
		var res [4]byte
		binary.BigEndian.PutUint32(res[:], uint32(v))
		ret = append(ret, res[:]...)
	}
	return ret
}

func TestDefaultDoPBKDF2(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		password, salt, expected string
	}{
		{"", "", "4fc58a21c100ce1835b8f9991d738b56"},
		{"abc", "abc", "9b6250eaeefa20cdd0d578a209f62cae"},
		{"cga4233", "ruf32WxGYH98", "8426009cb456f0f51c60d8aad75533b9"},
		{"4fc58a21c100ce1835b8f9991d738b56", "9b6250eaeefa20cdd0d578a209f62cae",
			"0e5342eb6a83579c08731231c3e91ed1"},
		{"cga4233", "zkLfX9ED5GY=", "bf9c2cd234ce90a128a02392aac85ec2"},
	}

	for i, tc := range testCases {
		got := defaultDoPBKDF2([]byte(tc.password), []byte(tc.salt))
		if string(got) != tc.expected {
			t.Errorf("[#%v] expected %q, got %q", i, tc.expected, string(got))
		}
	}
}

func TestDoPBKDF2WebUI(t *testing.T) {
	t.Parallel()

	const (
		pass      = "cga4233"
		salt      = "ruf32WxGYH98"
		saltWebUI = "a1etwcG3XV7P"
		iter      = 1000
		keyLen    = 16

		expected = "c9d58f0aea815d7cabe566663aa87495"
	)

	got := doPBKDF2WebUI([]byte(pass), []byte(salt), []byte(saltWebUI), iter, keyLen)
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestNewPasswordChangeRequestBody(t *testing.T) {
	t.Parallel()

	// test input data (shared with the javascript test)
	const (
		user                 = "custadmin"
		oldPass              = "cga4233"
		newPass              = "Cga42331"
		saltB64              = "zkLfX9ED5GY="
		rndCrap              = "N6F3cd9EK2XGas4VEakhP"
		saltBeforeEncryptB64 = "lur7srJozFE="
	)
	iv := sjclWordsToBytes([]int32{1481851925, 189938307, 761893355, -287649142})
	saltBeforeEncrypt := sjclWordsToBytes([]int32{-1762985038, -1301754799})

	// expected results
	expected := `{
	  "myusername": "custadmin",
	  "login_password": "{\"iv\":\"WFNEFQtSOoMtaZHr7trSig==\",\"v\":1,\"iter` +
		`\":1000,\"ks\":128,\"ts\":64,\"mode\":\"cbc\",\"adata\":\"\",\"` +
		`cipher\":\"aes\",\"salt\":\"lur7srJozFE=\",\"ct\":\"` +
		`1azTPJuZR445LX1HahU/GMjubyDBmbh47+cfqaPdwJ14CqntqbZSRW3HHEffDc8m\"}",
	  "login_salt": "N6F3cd9EK2X",
	  "login_salt3": "Gas4VEakhP"
	}`

	// process expected results
	var expectedMap map[string]string
	if err := json.Unmarshal([]byte(expected), &expectedMap); err != nil {
		t.Fatalf("test setup failed decoding expected JSON data: %v", err)
	}
	var expectedLoginPassword map[string]any
	if err := json.Unmarshal([]byte(expectedMap["login_password"]),
		&expectedLoginPassword); err != nil {
		t.Fatalf("test setup failed decoding expected JSON login password: %v",
			err)
	}

	// execute and get results
	res, err := newPasswordChangeRequestBody(user, oldPass, newPass,
		[]byte(saltB64), []byte(rndCrap), iv, saltBeforeEncrypt)
	if err != nil {
		t.Fatalf("test execution failed: %v", err)
	}

	// decode test results
	resURL, err := url.Parse("?" + res)
	if err != nil {
		t.Fatalf("URL-decoding execution results failed: %v", err)
	}
	resQuery := resURL.Query()
	var gotLoginPassword map[string]any
	if err := json.Unmarshal([]byte(resQuery.Get("login_password")),
		&gotLoginPassword); err != nil {
		t.Fatalf("JSON-decoding login_password execution results failed: %v",
			err)
	}

	// assert equality
	if x, g := expectedMap["login_salt"], resQuery.Get("login_salt"); x != g {
		t.Errorf("login_salt expected: %q; got:%q", x, g)
	}

	if x, g := expectedMap["login_salt3"], resQuery.Get("login_salt3"); x != g {
		t.Errorf("login_salt3 expected: %q; got:%q", x, g)
	}

	if x, g := len(expectedLoginPassword), len(gotLoginPassword); x != g {
		t.Errorf("expected login_password length: %v; got %v", x, g)
	}

	for k, x := range expectedLoginPassword {
		g, ok := gotLoginPassword[k]
		if !ok {
			t.Errorf("missing key in login_password obtained: %q", k)
		} else if x != g {
			t.Errorf("login_password[%s]: expected %T(%v); got %T(%v)", k, x, x,
				g, g)
		}
	}
}
