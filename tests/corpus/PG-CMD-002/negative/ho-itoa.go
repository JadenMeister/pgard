// corpus: expect=none
package ops

import (
	"os/exec"
	"strconv"
)

func Tail(n int) ([]byte, error) {
	return exec.Command("tail", "-n", strconv.Itoa(n), "/var/log/app.log").Output()
}
