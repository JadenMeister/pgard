// corpus: expect=PG-SQL-003
package store

import "database/sql"

func Delete(db *sql.DB, name string) error {
	_, err := db.Exec("DELETE FROM sessions WHERE owner = '" + name + "'")
	return err
}
