// corpus: expect=none; known=fp:PG-SQL-003:fmt.Sprintf with only a package constant is reported as dynamic SQL
package store

import (
	"database/sql"
	"fmt"
)

const table = "audit_log"

func Recent(db *sql.DB) (*sql.Rows, error) {
	// Only a package constant is formatted in.
	return db.Query(fmt.Sprintf("SELECT * FROM %s ORDER BY id DESC LIMIT 10", table))
}
