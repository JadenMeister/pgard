// corpus: expect=none
package ops

import "os/exec"

func Backup() error {
	return exec.Command("sh", "/opt/scripts/backup.sh").Run()
}
