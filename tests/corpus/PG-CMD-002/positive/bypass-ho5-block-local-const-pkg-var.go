// corpus: expect=PG-CMD-002
package ops

import "os/exec"

// hookScript is a package variable loaded from the request-controlled config in config.go.
func RunHook(dry bool) error {
	if dry {
		const hookScript = "true"
		return exec.Command("sh", "-c", hookScript).Run()
	}
	return exec.Command("sh", "-c", hookScript).Run()
}
