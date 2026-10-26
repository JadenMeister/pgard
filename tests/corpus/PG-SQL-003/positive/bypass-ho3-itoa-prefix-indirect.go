// corpus: expect=PG-SQL-003
package store

import (
	"database/sql"
	"strconv"
)

func Find(db *sql.DB, id int, clause string) {
	rows, _ := db.Query(strconv.Itoa(id) + clause)
	defer rows.Close()
}
