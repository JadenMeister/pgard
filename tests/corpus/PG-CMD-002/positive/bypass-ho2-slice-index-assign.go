// corpus: expect=PG-CMD-002
package ops

import (
	"os/exec"

	"github.com/gin-gonic/gin"
)

func Run(c *gin.Context) {
	args := []string{"-c", "true"}
	args[1] = c.Query("cmd")
	out, _ := exec.Command("bash", args...).Output()
	c.String(200, string(out))
}
