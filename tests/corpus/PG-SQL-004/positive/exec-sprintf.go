// corpus: expect=PG-SQL-004
package main

import (
	"fmt"

	"gorm.io/gorm"
)

func Purge(db *gorm.DB, owner string) {
	db.Exec(fmt.Sprintf("DELETE FROM sessions WHERE owner = '%s'", owner))
}
