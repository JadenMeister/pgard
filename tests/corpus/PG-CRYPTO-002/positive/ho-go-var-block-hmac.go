// corpus: expect=PG-CRYPTO-002
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
)

var (
	webhookSecret = []byte("hardcoded-webhook-secret")
)

func Sign(body []byte) []byte {
	mac := hmac.New(sha256.New, webhookSecret)
	mac.Write(body)
	return mac.Sum(nil)
}
