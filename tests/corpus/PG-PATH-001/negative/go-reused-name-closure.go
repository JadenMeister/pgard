// corpus: expect=none
package main

import (
	"os"

	"github.com/gin-gonic/gin"
)

func lookup(c *gin.Context) string {
	file := c.Query("file")
	return file
}

func reload() {
	load := func() {
		file := "/etc/app/default.conf"
		os.ReadFile(file)
	}
	load()
}
