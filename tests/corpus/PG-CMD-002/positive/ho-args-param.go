// corpus: expect=PG-CMD-002
package ops

import (
	"context"
	"os/exec"
)

func Run(ctx context.Context, args []string) error {
	return exec.CommandContext(ctx, "bash", args...).Run()
}
