// corpus: expect=PG-SQL-004
package main

import (
	"fmt"

	"gorm.io/gorm"
)

type User struct{ ID uint }

func Find(db *gorm.DB, table string) []User {
	var users []User
	db.Joins(fmt.Sprintf("JOIN %s ON %s.user_id = users.id", table, table)).Find(&users)
	return users
}
