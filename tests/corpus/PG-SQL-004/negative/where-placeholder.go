// corpus: expect=none
package main

import "gorm.io/gorm"

type User struct{ Name string }

func Find(db *gorm.DB, name string) []User {
	var users []User
	db.Where("name = ?", name).Find(&users)
	return users
}
