package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

/*
Auth Service Migration CLI
==========================

Usage:
  go run cmd/migrate/main.go up                    # Apply all migrations
  go run cmd/migrate/main.go down                  # Rollback all migrations
  go run cmd/migrate/main.go down 1                # Rollback 1 migration
  go run cmd/migrate/main.go version               # Show current version
  go run cmd/migrate/main.go status                # Show migration status
  go run cmd/migrate/main.go create <name>         # Create new migration
  go run cmd/migrate/main.go force <version>       # Force set version

Environment:
  DATABASE_URL is read from .env file or environment
*/

func main() {
	// Load .env file if exists
	_ = godotenv.Load()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	migrationsPath := "./migrations"

	switch command {
	case "create":
		if len(os.Args) < 3 {
			log.Fatal("Error: migration name required. Usage: migrate create <name>")
		}
		createMigration(migrationsPath, os.Args[2])
		return

	case "up", "down", "version", "status", "force":
		dbURL := os.Getenv("DATABASE_URL")
		if dbURL == "" {
			// Build from individual components
			dbURL = buildDatabaseURL()
		}
		if dbURL == "" {
			log.Fatal("Error: DATABASE_URL required. Set in .env or environment")
		}
		runMigration(command, dbURL, migrationsPath, os.Args[2:])

	default:
		log.Fatalf("Unknown command: %s", command)
	}
}

func buildDatabaseURL() string {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	sslmode := os.Getenv("DB_SSLMODE")

	if host == "" || user == "" || dbname == "" {
		return ""
	}
	if port == "" {
		port = "5432"
	}
	if sslmode == "" {
		sslmode = "disable"
	}

	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		user, password, host, port, dbname, sslmode)
}

func runMigration(command, dbURL, migrationsPath string, args []string) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		log.Fatalf("Failed to create driver: %v", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", migrationsPath),
		"postgres",
		driver,
	)
	if err != nil {
		log.Fatalf("Failed to create migrator: %v", err)
	}

	switch command {
	case "up":
		if len(args) > 0 {
			steps := parseSteps(args[0])
			err = m.Steps(steps)
		} else {
			err = m.Up()
		}
		if err != nil && err != migrate.ErrNoChange {
			log.Fatalf("Migration failed: %v", err)
		}
		printVersion(m)
		fmt.Println("✅ Migration completed successfully")

	case "down":
		steps := 1
		if len(args) > 0 {
			steps = parseSteps(args[0])
		}
		err = m.Steps(-steps)
		if err != nil && err != migrate.ErrNoChange {
			log.Fatalf("Rollback failed: %v", err)
		}
		printVersion(m)
		fmt.Println("✅ Rollback completed successfully")

	case "version":
		printVersion(m)

	case "status":
		printStatus(m)

	case "force":
		if len(args) < 1 {
			log.Fatal("Error: version required for force command")
		}
		v := parseSteps(args[0])
		if err := m.Force(v); err != nil {
			log.Fatalf("Force failed: %v", err)
		}
		fmt.Printf("✅ Forced version to %d\n", v)
	}
}

func parseSteps(s string) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		log.Fatalf("Invalid number: %s", s)
	}
	return n
}

func printVersion(m *migrate.Migrate) {
	v, dirty, err := m.Version()
	if err != nil {
		if err == migrate.ErrNilVersion {
			fmt.Println("📋 No migrations applied")
			return
		}
		log.Fatalf("Failed: %v", err)
	}
	status := ""
	if dirty {
		status = " ⚠️  DIRTY"
	}
	fmt.Printf("📋 Current version: %d%s\n", v, status)
}

func printStatus(m *migrate.Migrate) {
	v, dirty, err := m.Version()
	fmt.Println("╔════════════════════════════════════════╗")
	fmt.Println("║        Migration Status                ║")
	fmt.Println("╠════════════════════════════════════════╣")

	if err != nil {
		if err == migrate.ErrNilVersion {
			fmt.Println("║ Status: No migrations applied          ║")
			fmt.Println("║ Run 'migrate up' to apply              ║")
			fmt.Println("╚════════════════════════════════════════╝")
			return
		}
		log.Fatalf("Error: %v", err)
	}

	if dirty {
		fmt.Printf("║ Version: %-29d ║\n", v)
		fmt.Println("║ Status:  DIRTY (needs manual fix)      ║")
		fmt.Println("║ Use 'migrate force <version>' to fix   ║")
	} else {
		fmt.Printf("║ Version: %-29d ║\n", v)
		fmt.Println("║ Status:  OK                             ║")
	}
	fmt.Println("╚════════════════════════════════════════╝")
}

func createMigration(path, name string) {
	if err := os.MkdirAll(path, 0755); err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}

	entries, _ := os.ReadDir(path)
	version := 1
	for _, e := range entries {
		var v int
		if _, err := fmt.Sscanf(e.Name(), "%d_", &v); err == nil && v >= version {
			version = v + 1
		}
	}

	upFile := fmt.Sprintf("%s/%06d_%s.up.sql", path, version, name)
	downFile := fmt.Sprintf("%s/%06d_%s.down.sql", path, version, name)

	upContent := fmt.Sprintf("-- Migration: %s\n-- Version: %d\n\n-- Write your UP migration here\n\n", name, version)
	downContent := fmt.Sprintf("-- Rollback: %s\n-- Version: %d\n\n-- Write your DOWN migration here\n\n", name, version)

	if err := os.WriteFile(upFile, []byte(upContent), 0644); err != nil {
		log.Fatalf("Failed: %v", err)
	}
	if err := os.WriteFile(downFile, []byte(downContent), 0644); err != nil {
		os.Remove(upFile)
		log.Fatalf("Failed: %v", err)
	}

	fmt.Println("✅ Migration files created:")
	fmt.Printf("   📄 %s\n", upFile)
	fmt.Printf("   📄 %s\n", downFile)
}

func printUsage() {
	fmt.Println(`
Auth Service Migration Tool
===========================

Commands:
  up [n]          Apply all (or n) pending migrations
  down [n]        Rollback last n migrations (default: 1)
  version         Show current migration version
  status          Show detailed migration status
  create <name>   Create new migration files
  force <version> Force set migration version (fix dirty state)

Examples:
  migrate up              # Apply all pending migrations
  migrate down 1          # Rollback last migration
  migrate create add_mfa  # Create new migration files
  migrate status          # Check current status

Environment:
  Set DATABASE_URL or individual DB_* variables in .env file`)
}
