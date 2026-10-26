// corpus: expect=none
package auth

import (
	"os"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey []byte

func init() {
	jwtKey = []byte(os.Getenv("JWT_KEY"))
}

func Issue(sub string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": sub})
	return t.SignedString(jwtKey)
}
