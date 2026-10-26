// corpus: expect=none
package files

import (
	"crypto/sha256"
	"encoding/hex"
)

func Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
