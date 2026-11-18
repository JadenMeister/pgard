// corpus: expect=PG-PATH-001
package main

import (
	"os"

	"github.com/gin-gonic/gin"
)

func download(c *gin.Context) {
	file := c.Query("file")
	send := func() {
		data, _ := os.ReadFile(file)
		c.Data(200, "text/plain", data)
	}
	send()
}
