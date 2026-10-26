// corpus: expect=PG-CRYPTO-002; known=miss:PG-CRYPTO-002:a hardcoded key held in a package variable and passed to SignedString is not followed
package auth

import "github.com/golang-jwt/jwt/v5"

var signingKey = []byte("hardcoded-signing-secret")

func Issue(sub string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": sub})
	return t.SignedString(signingKey)
}
