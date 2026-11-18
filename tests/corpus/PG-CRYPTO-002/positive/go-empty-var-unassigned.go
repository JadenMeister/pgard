// corpus: expect=PG-CRYPTO-002
package auth

import "github.com/golang-jwt/jwt/v5"

// Never assigned: the HMAC key is empty.
var jwtKey = []byte("")

func Issue(sub string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": sub})
	return t.SignedString(jwtKey)
}
