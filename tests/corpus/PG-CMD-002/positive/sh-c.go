// corpus: expect=PG-CMD-002
package main

import (
	"net/http"
	"os/exec"
)

func logHandler(w http.ResponseWriter, r *http.Request) {
	ref := r.URL.Query().Get("ref")
	out, _ := exec.Command("sh", "-c", "git log "+ref).Output()
	w.Write(out)
}
