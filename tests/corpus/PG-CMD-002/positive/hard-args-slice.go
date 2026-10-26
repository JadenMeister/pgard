// corpus: expect=PG-CMD-002
package ops

import "os/exec"

func Run(script string) error {
	args := []string{"-c", script}
	return exec.Command("sh", args...).Run()
}
