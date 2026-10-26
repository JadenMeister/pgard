// corpus: expect=none; allow=low
package ops

import "os/exec"

func Uptime() ([]byte, error) {
	args := []string{"-c", "uptime"}
	return exec.Command("sh", args...).Output()
}
