// corpus: expect=none
package main

import "gorm.io/gorm"

type User struct {
	Name string
	Age  int
}

func Find(db *gorm.DB, name string) []User {
	var users []User
	db.Where(&User{Name: name}).Find(&users)
	return users
}
