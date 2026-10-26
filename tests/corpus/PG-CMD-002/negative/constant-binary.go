// corpus: expect=none
package ops

import "os/exec"

func Version() (string, error) {
	out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").Output()
	return string(out), err
}
