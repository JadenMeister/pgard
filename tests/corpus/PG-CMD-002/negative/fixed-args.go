// corpus: expect=none
package ops

import "os/exec"

func Log(ref string) ([]byte, error) {
	return exec.Command("git", "log", "--end-of-options", ref, "--").Output()
}
