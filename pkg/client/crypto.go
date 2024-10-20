package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/diegommm/technicolor-cga4233tch3/pkg/httpdoer"
	"golang.org/x/crypto/pbkdf2"
)

const (
	defaultPBKDF2iter        = 1000
	defaultPBKDF2keyLenBytes = 16
)

func hexEncode(v []byte) []byte {
	ret := make([]byte, hex.EncodedLen(len(v)))
	n := hex.Encode(ret, v)
	return ret[:n]
}

// doPBKDF2 derives a PBKDF2 key from the given parameters.
func doPBKDF2(password, salt []byte, iter, keyLenBytes int) []byte {
	ret := pbkdf2.Key(password, salt, iter, keyLenBytes, sha256.New)
	return hexEncode(ret)
}

func defaultDoPBKDF2(password, salt []byte) []byte {
	return doPBKDF2(password, salt, defaultPBKDF2iter, defaultPBKDF2keyLenBytes)
}

// doPBKDF2WebUI calls DoPBKDF2 first with `salt`, and its results are used as
// password in a second round using `saltWebUI` as salt.
func doPBKDF2WebUI(password, salt, saltWebUI []byte, iter, keyLenBytes int) string {
	res := doPBKDF2(password, salt, iter, keyLenBytes)
	res = doPBKDF2(res, saltWebUI, iter, keyLenBytes)
	return string(res)
}

var noneStr = []byte("none")

// derivePasswordWebUI derives the password from the given parameters returned
// by the `seeksalthash` stage of the login process, so that it can be used as
// the password for the second stage.
func derivePasswordWebUI(password, salt, saltWebUI []byte, iter, keyLenBytes int) string {
	if slices.Equal(salt, noneStr) {
		return string(password)
	}
	return doPBKDF2WebUI(password, salt, saltWebUI, iter, keyLenBytes)
}

// DefaultDerivePasswordWebUI calls DerivePasswordWebUI with the default values
// for `iter` and `keyLenBytes`.
func DefaultDerivePasswordWebUI(password, salt, saltWebUI []byte) string {
	return derivePasswordWebUI(password, salt, saltWebUI, defaultPBKDF2iter,
		defaultPBKDF2keyLenBytes)
}

const b62dict = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func randomBase62(length int) ([]byte, error) {
	p := make([]byte, length)
	if _, err := rand.Read(p); err != nil {
		return nil, err
	}
	for i := range p {
		// this is flawed but good enough: we're introducing a bias towards the
		// first 2^8 % len(b62dict) elements of the dictionary
		p[i] = b62dict[int(p[i])%len(b62dict)]
	}
	return p, nil
}

func makeRandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// aes-128-cbc encrypts to ciphertext with the given params. Requirements:
//   - `key` and `iv` must have length 16.
//   - `plaintext` and `ciphertext` must be the same length.
//   - `plaintext` must have a length multiple of 16.
func aes128cbc(key, iv, plaintext []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	plaintext = addPKCS5Padding(plaintext)
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(b, iv).CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

func addPKCS5Padding(plaintext []byte) []byte {
	ret := make([]byte, 0, len(plaintext)+16)
	ret = append(ret, plaintext...)

	var pad4 [4]byte
	bl := uint32((16 - (len(plaintext) & 15)) * 0x1010101)
	binary.BigEndian.PutUint32(pad4[:], uint32(bl))
	for i := 0; i < 4; i++ {
		ret = append(ret, pad4[:]...)
	}

	return ret
}

func defaultNewPasswordChangeRequestBody(
	newUser string,
	oldPass string,
	newPass string,
	oldPassSalt []byte,
) (string, error) {
	rndBase62, err := randomBase62(22)
	if err != nil {
		return "", fmt.Errorf("generate 22 bytes of random base 62: %w", err)
	}
	aesIV, err := makeRandomBytes(16)
	if err != nil {
		return "", fmt.Errorf("generate 16 bytes for AES IV: %w", err)
	}
	newPassSalt, err := makeRandomBytes(8)
	if err != nil {
		return "", fmt.Errorf("generate 8 bytes for new pass salt: %w", err)
	}

	return newPasswordChangeRequestBody(newUser, oldPass, newPass, oldPassSalt,
		rndBase62, aesIV, newPassSalt)
}

// generatePasswordChangeRequestBody is a complex bullshit that the authors of
// the firmware tried to use to somewhat make it more "secure". But it's not.
// This function is idempotent to make it easier to test, but consider using the
// simpler defaultNewPasswordChangeRequestBody, which generates random data for
// you and requires only minimal input.
func newPasswordChangeRequestBody(
	newUser string,
	oldPass string,
	newPass string,
	oldPassSalt []byte,

	// should be generated each time:
	rndBase62 []byte, // 22 bytes of random base 62. Use randomBase62 to generate
	aesIV []byte, // AES initialization vector, 16 bytes
	newPassSalt []byte, // 8 bytes to use as salt to add one more PBKDF2 step before using the AES key
) (string, error) {
	salt1prime, salt3 := rndBase62[:11], rndBase62[11:]
	hash1prime := defaultDoPBKDF2([]byte(newPass), salt1prime)
	hash1 := defaultDoPBKDF2([]byte(oldPass), oldPassSalt)
	hash3 := defaultDoPBKDF2([]byte(hash1), salt3)

	encryptionKey := pbkdf2.Key(hash3, newPassSalt, 1000, 16, sha256.New)

	ciphertext, err := aes128cbc(encryptionKey, aesIV, hash1prime)
	if err != nil {
		return "", fmt.Errorf("encrypt with aes-128-cbc: %w", err)
	}

	sd := sjclData{
		IV:                base64.StdEncoding.EncodeToString(aesIV),
		V:                 1,
		Iter:              1000,
		KeySize:           128,
		TagSize:           64,
		Mode:              "cbc",
		AuthenticatedData: "",
		Cipher:            "aes",
		Salt:              base64.StdEncoding.EncodeToString(newPassSalt),
		CipherText:        base64.StdEncoding.EncodeToString(ciphertext),
	}

	b := new(strings.Builder)
	if err := json.NewEncoder(b).Encode(sd); err != nil {
		return "", fmt.Errorf("JSON-encode sjcl data: %w", err)
	}

	return httpdoer.KeyValue{
		"login_salt":     string(salt1prime),
		"login_salt3":    string(salt3),
		"login_password": b.String(),
		"myusername":     newUser,
	}.ToURLValues().Encode(), nil
}
