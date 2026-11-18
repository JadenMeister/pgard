// corpus: expect=none
package main

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

// Reads request input into `name` but never uses it as a path.
func greet(c *gin.Context) {
	name := c.Query("name")
	c.String(http.StatusOK, "hello "+name)
}

func report(c *gin.Context) {
	name := "monthly-report.txt"
	data, _ := os.ReadFile(filepath.Join("/srv/reports", name))
	c.Data(http.StatusOK, "text/plain", data)
}
