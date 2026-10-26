// corpus: expect=none
package main

import (
	"database/sql"

	"gorm.io/gorm"
)

func Search(db *gorm.DB, term string) {
	var out []map[string]any
	db.Raw("SELECT * FROM posts WHERE title LIKE @term", sql.Named("term", "%"+term+"%")).Scan(&out)
}
