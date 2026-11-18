// corpus: expect=low
package auth

import "github.com/golang-jwt/jwt/v5"

// The key is filled in from the environment by another file of the package (keys.go).
var jwtKey = []byte("")

func Issue(sub string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": sub})
	return t.SignedString(jwtKey)
}
