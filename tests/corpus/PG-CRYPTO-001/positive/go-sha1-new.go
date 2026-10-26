// corpus: expect=PG-CRYPTO-001
package auth

import (
	"crypto/sha1"
	"encoding/hex"
)

func HashPassword(password string) string {
	h := sha1.New()
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}
