// corpus: expect=PG-SQL-003
package main

import (
	"database/sql"
	"net/http"
)

func readSort(r *http.Request) (sort string) {
	sort = r.URL.Query().Get("sort")
	return
}

func list(db *sql.DB, r *http.Request) {
	sort := readSort(r)
	db.Query("SELECT * FROM t ORDER BY " + sort)
}
