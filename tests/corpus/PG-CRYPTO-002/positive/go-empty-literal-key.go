// corpus: expect=PG-CRYPTO-002
package auth

import "github.com/golang-jwt/jwt/v5"

func Issue(sub string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": sub})
	return t.SignedString([]byte(""))
}
