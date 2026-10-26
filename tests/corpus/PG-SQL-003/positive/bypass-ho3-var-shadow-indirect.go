// corpus: expect=PG-SQL-003
package store

import (
	"database/sql"
	"net/http"
)

const table = "users"

func pick(r *http.Request) string { return r.URL.Query().Get("t") }

func List(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	var table = pick(r)
	rows, _ := db.Query("SELECT * FROM " + table)
	defer rows.Close()
}
