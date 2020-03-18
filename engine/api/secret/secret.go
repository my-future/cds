package secret

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"github.com/ovh/cds/sdk"
	"github.com/ovh/cds/sdk/log"
)

// AES key fetched
const (
	nonceSize = aes.BlockSize
	macSize   = 32
	ckeySize  = 32
)

var (
	key    []byte
	prefix = "3DICC3It"
)

// Init secrets: cipherKey
// cipherKey is set from viper configuration
func Init(cipherKey string) {
	key = []byte(cipherKey)
}

// Encrypt data using aes+hmac algorithm
// Init() must be called before any encryption
func Encrypt(data []byte) ([]byte, error) {
	// Check key is ready
	if key == nil {
		log.Error(context.TODO(), "Missing key, init failed?")
		return nil, sdk.ErrSecretKeyFetchFailed
	}
	// generate nonce
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// init aes cipher
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ctr := cipher.NewCTR(c, nonce)
	// encrypt data
	ct := make([]byte, len(data))
	ctr.XORKeyStream(ct, data)
	// add hmac
	h := hmac.New(sha256.New, key[ckeySize:])
	ct = append(nonce, ct...)
	h.Write(ct)
	ct = h.Sum(ct)

	return append([]byte(prefix), ct...), nil
}

// Decrypt data using aes+hmac algorithm
// Init() must be called before any decryption
func Decrypt(data []byte) ([]byte, error) {
	if !strings.HasPrefix(string(data), prefix) {
		return data, nil
	}
	data = []byte(strings.TrimPrefix(string(data), prefix))

	if key == nil {
		log.Error(context.TODO(), "Missing key, init failed?")
		return nil, sdk.WithStack(sdk.ErrSecretKeyFetchFailed)
	}

	if len(data) < (nonceSize + macSize) {
		log.Error(context.TODO(), "cannot decrypt secret, got invalid data")
		return nil, sdk.WithStack(sdk.ErrInvalidSecretFormat)
	}

	// Split actual data, hmac and nonce
	macStart := len(data) - macSize
	tag := data[macStart:]
	out := make([]byte, macStart-nonceSize)
	data = data[:macStart]
	// check hmac
	h := hmac.New(sha256.New, key[ckeySize:])
	h.Write(data)
	mac := h.Sum(nil)
	if !hmac.Equal(mac, tag) {
		return nil, sdk.WithStack(fmt.Errorf("invalid hmac"))
	}
	// uncipher data
	c, err := aes.NewCipher(key[:ckeySize])
	if err != nil {
		return nil, sdk.WithStack(fmt.Errorf("unable to create cypher block: %v", err))
	}
	ctr := cipher.NewCTR(c, data[:nonceSize])
	ctr.XORKeyStream(out, data[nonceSize:])
	return out, nil
}
