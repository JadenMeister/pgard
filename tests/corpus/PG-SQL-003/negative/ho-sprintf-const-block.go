// corpus: expect=none
package store

import (
	"database/sql"
	"fmt"
)

const (
	schema = "reporting"
	limit  = 50
)

func Latest(db *sql.DB) (*sql.Rows, error) {
	q := fmt.Sprintf("SELECT * FROM %s.events ORDER BY id DESC LIMIT %d", schema, limit)
	return db.Query(q)
}
