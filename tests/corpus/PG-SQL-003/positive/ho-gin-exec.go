// corpus: expect=PG-SQL-003
package handlers

import (
	"database/sql"

	"github.com/gin-gonic/gin"
)

func Remove(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, _ = db.Exec("DELETE FROM sessions WHERE token = '" + c.Query("token") + "'")
		c.Status(204)
	}
}
