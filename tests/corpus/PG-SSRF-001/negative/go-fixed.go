// corpus: expect=none
package main

import "net/http"

func health() (*http.Response, error) {
	return http.Get("https://status.example.com/health")
}
