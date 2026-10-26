// corpus: expect=PG-CMD-002; known=miss:PG-CMD-002:arguments passed as a spread slice (args...) are not inspected for a shell invocation
package ops

import "os/exec"

func Run(script string) error {
	args := []string{"-c", script}
	return exec.Command("sh", args...).Run()
}
