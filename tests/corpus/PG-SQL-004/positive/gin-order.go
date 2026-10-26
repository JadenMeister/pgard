// corpus: expect=PG-SQL-004
package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Post struct{ ID uint }

func List(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var posts []Post
		db.Order(fmt.Sprintf("%s desc", c.Query("sort"))).Find(&posts)
		c.JSON(200, posts)
	}
}
