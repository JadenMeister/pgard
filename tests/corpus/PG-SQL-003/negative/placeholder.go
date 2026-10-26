// corpus: expect=none
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query("SELECT * FROM users WHERE id = $1", r.URL.Query().Get("id"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer rows.Close()
	}
}
