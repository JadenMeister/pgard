// corpus: expect=PG-CMD-002
package ops

import "os/exec"

func defaultHook() string {
	const hookCmd = "true"
	return hookCmd
}

// hookCmd is a package variable configured per request in config.go.
func RunHook() ([]byte, error) {
	return exec.Command("sh", "-c", hookCmd).Output()
}
