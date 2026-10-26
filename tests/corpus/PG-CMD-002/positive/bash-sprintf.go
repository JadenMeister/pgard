// corpus: expect=PG-CMD-002
package ops

import (
	"fmt"
	"os/exec"
)

func Archive(dir string) error {
	return exec.Command("bash", "-c", fmt.Sprintf("tar czf out.tgz %s", dir)).Run()
}
