// corpus: expect=PG-SQL-003
package store

import "database/sql"

func Find(db *sql.DB, id string) (*sql.Rows, error) {
	query := "SELECT * FROM users WHERE 1=1"
	query += " AND id = " + id
	return db.Query(query)
}
