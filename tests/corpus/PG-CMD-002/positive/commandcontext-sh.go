// corpus: expect=PG-CMD-002
package ops

import (
	"context"
	"os/exec"
)

func Ping(ctx context.Context, host string) ([]byte, error) {
	return exec.CommandContext(ctx, "/bin/sh", "-c", "ping -c1 "+host).Output()
}
