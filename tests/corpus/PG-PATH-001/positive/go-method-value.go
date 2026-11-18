// corpus: expect=PG-PATH-001
package main

import (
	"os"

	"github.com/gin-gonic/gin"
)

type store struct{}

func (s *store) Read(name string) { os.ReadFile(name) }

func download(c *gin.Context, s *store) {
	name := c.Query("n")
	read := s.Read
	read(name)
}
