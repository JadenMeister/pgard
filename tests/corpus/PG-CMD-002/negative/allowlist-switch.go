// corpus: expect=none
package ops

import "os/exec"

func Run(action string) error {
	switch action {
	case "restart":
		return exec.Command("systemctl", "restart", "app").Run()
	case "status":
		return exec.Command("systemctl", "status", "app").Run()
	}
	return nil
}
