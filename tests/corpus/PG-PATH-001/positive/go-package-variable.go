// corpus: expect=PG-PATH-001
package main

import (
	"os"

	"github.com/gin-gonic/gin"
)

var target string

func choose(c *gin.Context) {
	target = c.Query("path")
}

func download(c *gin.Context) {
	data, _ := os.ReadFile(target)
	c.Data(200, "text/plain", data)
}
