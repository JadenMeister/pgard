// corpus: expect=none
package store

import "database/sql"

func Lookup(db *sql.DB, id int) (string, error) {
	stmt, err := db.Prepare("SELECT name FROM users WHERE id = ?")
	if err != nil {
		return "", err
	}
	defer stmt.Close()
	var name string
	err = stmt.QueryRow(id).Scan(&name)
	return name, err
}
