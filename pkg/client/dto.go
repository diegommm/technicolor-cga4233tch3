package client

import (
	"encoding/json"
	"fmt"
	"strings"
)

type response struct {
	Error   string         `json:"error"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data"`
}

func (r response) Validate() error {
	if strings.ToLower(r.Error) != "ok" {
		return fmt.Errorf("unexpected error: %v; message: %v; data: %#v",
			r.Error, r.Message, r.Data)
	}
	return nil
}

type loginResponse struct {
	response

	// fields only set when password was "seeksalthash"

	Salt      json.RawMessage `json:"salt"`
	SaltWebUI json.RawMessage `json:"saltwebui"`
}

type sjclData struct {
	Cipher            string `json:"cipher"` // aes
	Mode              string `json:"mode"`   // cbc
	IV                string `json:"iv"`     // initialization vector (16 bytes) in base64
	Salt              string `json:"salt"`   // salt (16 bytes)
	AuthenticatedData string `json:"adata"`  // (optional) non-encrypted but authenticated message in base64 (ignored in cbc)
	CipherText        string `json:"ct"`     // encryption result in base64
	V                 int    `json:"v"`      // version? Always 1
	Iter              int    `json:"iter"`   // 1000 (for pbkdf2)
	KeySize           int    `json:"ks"`     // 128 bits
	TagSize           int    `json:"ts"`     // Not relevant for cbc but always 64
}
