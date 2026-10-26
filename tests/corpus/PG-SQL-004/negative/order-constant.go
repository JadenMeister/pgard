// corpus: expect=none
package main

import "gorm.io/gorm"

type Post struct{ ID uint }

func Latest(db *gorm.DB) []Post {
	var posts []Post
	db.Order("created_at desc").Limit(10).Find(&posts)
	return posts
}
