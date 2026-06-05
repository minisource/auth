//go:build ignore

package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	email := getenv("ADMIN_EMAIL", "admin@example.com")
	password := getenv("ADMIN_PASSWORD", "AdminPass123!")
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		getenv("DB_HOST", "localhost"),
		getenv("DB_PORT", "5432"),
		getenv("DB_USER", "postgres"),
		getenv("DB_PASSWORD", "postgres_dev"),
		getenv("DB_NAME", "auth_db"),
	)

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	res, err := db.Exec(`UPDATE users SET password_hash = $1, updated_at = NOW() WHERE email = $2 AND deleted_at IS NULL`, string(hash), email)
	if err != nil {
		panic(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		panic(fmt.Sprintf("no user updated for email %s", email))
	}
	fmt.Printf("Admin password reset for %s => %s\n", email, password)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
