// corpus: expect=PG-PATH-001
package main

import (
	"os"

	"github.com/gin-gonic/gin"
)

func download(c *gin.Context) {
	name := c.Query("name")
	serve(c, name)
}

func serve(c *gin.Context, path string) {
	data, _ := os.ReadFile(path)
	c.Data(200, "text/plain", data)
}
