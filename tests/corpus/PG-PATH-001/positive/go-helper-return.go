// corpus: expect=PG-PATH-001
package main

import "net/http"

func getFilename(r *http.Request) string {
	filename := r.URL.Query().Get("file")
	return filename
}

func download(w http.ResponseWriter, r *http.Request) {
	filename := getFilename(r)
	http.ServeFile(w, r, "/data/"+filename)
}
