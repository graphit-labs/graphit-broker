package broker

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// DatabaseDialect isolates the SQL differences used by the control store. Domain persistence
// depends on this contract rather than on one database driver.
type DatabaseDialect interface {
	Name() string
	DriverName() string
	Bind(string) string
	InsertIgnore(string) string
}

type sqlDialect struct {
	name   string
	driver string
}

func (d sqlDialect) Name() string       { return d.name }
func (d sqlDialect) DriverName() string { return d.driver }

func (d sqlDialect) Bind(query string) string {
	if d.name != "postgres" {
		return query
	}
	var output strings.Builder
	parameter := 1
	for _, char := range query {
		if char == '?' {
			fmt.Fprintf(&output, "$%d", parameter)
			parameter++
		} else {
			output.WriteRune(char)
		}
	}
	return output.String()
}

func (d sqlDialect) InsertIgnore(query string) string {
	switch d.name {
	case "mysql":
		return strings.Replace(query, "INSERT INTO", "INSERT IGNORE INTO", 1)
	case "postgres", "sqlite":
		return query + " ON CONFLICT DO NOTHING"
	default:
		return query
	}
}

func resolveDatabaseDialect(name string) (DatabaseDialect, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sqlite":
		return sqlDialect{name: "sqlite", driver: "sqlite"}, nil
	case "postgres", "postgresql":
		return sqlDialect{name: "postgres", driver: "pgx"}, nil
	case "mysql":
		return sqlDialect{name: "mysql", driver: "mysql"}, nil
	default:
		return nil, fmt.Errorf("unsupported database driver %q", name)
	}
}

func openDatabase(ctx context.Context, cfg DatabaseConfig) (*sql.DB, DatabaseDialect, error) {
	dialect, err := resolveDatabaseDialect(cfg.Driver)
	if err != nil {
		return nil, nil, err
	}
	if dialect.Name() == "sqlite" {
		if err := secureSQLiteParent(cfg.DSN); err != nil {
			return nil, nil, err
		}
	}
	db, err := sql.Open(dialect.DriverName(), cfg.DSN)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s database: %w", dialect.Name(), err)
	}
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("connect to %s database: %w", dialect.Name(), err)
	}
	return db, dialect, nil
}

func secureSQLiteParent(dsn string) error {
	path := sqliteFilePath(dsn)
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create SQLite directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure SQLite directory: %w", err)
	}
	return nil
}

func secureSQLiteFile(dsn string) error {
	path := sqliteFilePath(dsn)
	if path == "" {
		return nil
	}
	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("secure SQLite database: %w", err)
	}
	return nil
}

func sqliteFilePath(dsn string) string {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" || dsn == ":memory:" || strings.Contains(dsn, "mode=memory") {
		return ""
	}
	if strings.HasPrefix(dsn, "file:") {
		path := strings.TrimPrefix(dsn, "file:")
		if index := strings.IndexByte(path, '?'); index >= 0 {
			path = path[:index]
		}
		return path
	}
	if strings.Contains(dsn, "?") {
		return strings.SplitN(dsn, "?", 2)[0]
	}
	return dsn
}
