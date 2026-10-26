// corpus: expect=PG-CRYPTO-001
package users

import (
	"crypto/md5"
	"encoding/hex"
)

func HashPassword(password string) string {
	sum := md5.Sum([]byte(password))
	return hex.EncodeToString(sum[:])
}
