// corpus: expect=PG-PATH-001
package main

import (
	"net/http"
	"os"
)

func download(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("/srv/files/" + r.URL.Query().Get("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}
