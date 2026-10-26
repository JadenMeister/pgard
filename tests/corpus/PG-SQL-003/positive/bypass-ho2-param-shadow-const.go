// corpus: expect=PG-SQL-003
package store

import (
	"database/sql"

	"github.com/gin-gonic/gin"
)

const col = "name"

func sortBy(db *sql.DB, col string) (*sql.Rows, error) {
	return db.Query("SELECT id FROM people ORDER BY " + col)
}

func Handler(c *gin.Context, db *sql.DB) {
	rows, _ := sortBy(db, c.Query("sort"))
	defer rows.Close()
}
