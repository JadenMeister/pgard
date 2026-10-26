// corpus: expect=none
package store

import "database/sql"

func Count(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow("SELECT count(*) " + "FROM users").Scan(&n)
	return n, err
}
