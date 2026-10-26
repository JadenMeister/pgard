// corpus: expect=PG-SQL-003
package store

import (
	"database/sql"
	"fmt"
	"net/http"
)

func Find(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	name := r.FormValue("name")
	return db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
}
