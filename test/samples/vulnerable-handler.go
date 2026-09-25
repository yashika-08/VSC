// test/samples/vulnerable-handler.go
// Sample file with intentional Go vulnerabilities for testing Sentinel-VSC

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

// ❌ VULNERABLE: Hardcoded credentials (auth-003)
var dbConfig = struct {
	password string
	api_key  string
}{
	password: "SuperSecret123!",
	api_key:  "sk-live-XXXXXXXXXXXXXXXX",
}

// ❌ VULNERABLE: SQL Injection — fmt.Sprintf in query (sqli-005)
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("postgres", "host=localhost dbname=app")
	userID := r.URL.Query().Get("id")

	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID))
}

// ❌ VULNERABLE: Command Injection — exec.Command with user input (cmdi-002)
func convertHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("filename")
	cmd := exec.Command(fmt.Sprintf("convert %s -resize 200x200 output.jpg", filename))
	cmd.Run()
}

// ❌ VULNERABLE: HTTP without TLS (misconfig-004)
func main() {
	http.HandleFunc("/user", getUserHandler)
	http.HandleFunc("/convert", convertHandler)
	http.ListenAndServe(":8080", nil)
}
