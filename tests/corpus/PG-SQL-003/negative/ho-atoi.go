// corpus: expect=low
package store

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
)

func Page(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	n, err := strconv.Atoi(r.FormValue("n"))
	if err != nil {
		return nil, err
	}
	return db.Query(fmt.Sprintf("SELECT * FROM posts LIMIT %d", n))
}
