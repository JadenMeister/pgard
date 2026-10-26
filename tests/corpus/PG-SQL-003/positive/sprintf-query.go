// corpus: expect=PG-SQL-003
package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func handler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer rows.Close()
	}
}
