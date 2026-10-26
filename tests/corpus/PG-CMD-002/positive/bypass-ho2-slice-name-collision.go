// corpus: expect=PG-CMD-002
package ops

import (
	"net/http"
	"os/exec"
)

func Uptime() {
	args := []string{"-c", "uptime"}
	exec.Command("sh", args...).Run()
}

func Ping(w http.ResponseWriter, r *http.Request) {
	args := []string{"-c", "ping -c 1 " + r.URL.Query().Get("host")}
	out, _ := exec.Command("sh", args...).Output()
	w.Write(out)
}
