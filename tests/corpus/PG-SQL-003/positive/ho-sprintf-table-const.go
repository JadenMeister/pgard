// corpus: expect=PG-SQL-003
package store

import (
	"database/sql"
	"fmt"
	"net/http"
)

const table = "audit_log"

func Search(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	// The table is a constant but the filter is request input.
	return db.Query(fmt.Sprintf("SELECT * FROM %s WHERE actor = '%s'", table, r.URL.Query().Get("actor")))
}
