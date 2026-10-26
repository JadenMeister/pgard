// corpus: expect=none
package store

import "database/sql"

const columns = "id, name, email"

func All(db *sql.DB) (*sql.Rows, error) {
	return db.Query("SELECT " + columns + " FROM users ORDER BY id")
}
