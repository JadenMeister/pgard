// corpus: expect=PG-SQL-003
package main

import (
	"database/sql"
	"fmt"

	"github.com/gin-gonic/gin"
)

func Show(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		row := db.QueryRow(fmt.Sprintf("SELECT name FROM users WHERE id = %s", c.Param("id")))
		var name string
		_ = row.Scan(&name)
		c.String(200, name)
	}
}
