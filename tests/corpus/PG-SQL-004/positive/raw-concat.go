// corpus: expect=PG-SQL-004
package main

import "gorm.io/gorm"

func Search(db *gorm.DB, term string) {
	var out []map[string]any
	db.Raw("SELECT * FROM posts WHERE title LIKE '%" + term + "%'").Scan(&out)
}
