// corpus: expect=PG-PATH-001
package main

import (
	"os"

	"github.com/gin-gonic/gin"
)

type request struct {
	Path string
}

func download(c *gin.Context) {
	req := request{Path: c.Query("path")}
	data, _ := os.ReadFile(req.Path)
	c.Data(200, "text/plain", data)
}
