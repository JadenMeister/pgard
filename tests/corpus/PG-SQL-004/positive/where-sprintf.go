// corpus: expect=PG-SQL-004
package main

import (
	"fmt"

	"gorm.io/gorm"
)

type User struct{ Name string }

func Find(db *gorm.DB, name string) []User {
	var users []User
	db.Where(fmt.Sprintf("name = '%s'", name)).Find(&users)
	return users
}
