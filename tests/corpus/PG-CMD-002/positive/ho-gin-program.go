// corpus: expect=PG-CMD-002
package ops

import (
	"os/exec"

	"github.com/gin-gonic/gin"
)

func Tool(c *gin.Context) {
	out, _ := exec.Command(c.Query("bin"), "--version").Output()
	c.String(200, string(out))
}
