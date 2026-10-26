// corpus: expect=none
package ops

import "os/exec"

func Cleanup() error {
	return exec.Command("sh", "-c", "rm -rf /var/tmp/app-cache && sync").Run()
}
