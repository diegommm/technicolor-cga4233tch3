package httpdoer

import (
	"net/http"
	"net/url"
)

type KeyValue map[string]string

func (kv KeyValue) ToMultiValues() map[string][]string {
	ret := make(map[string][]string, len(kv))
	for k, v := range kv {
		ret[k] = []string{v}
	}
	return ret
}

func (kv KeyValue) ToHTTPHeader() http.Header {
	return http.Header(kv.ToMultiValues())
}

func (kv KeyValue) ToURLValues() url.Values {
	return url.Values(kv.ToMultiValues())
}
