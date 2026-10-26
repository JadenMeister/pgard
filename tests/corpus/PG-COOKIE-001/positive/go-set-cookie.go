// corpus: expect=PG-COOKIE-001
package main

import "net/http"

func login(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "token", Path: "/"})
}
