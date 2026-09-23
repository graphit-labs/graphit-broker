package broker

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestOpenControlStoreConnectTimeout(t *testing.T) {
	short := time.Nanosecond
	cfg := DatabaseConfig{Driver: "sqlite", DSN: ":memory:", MaxOpenConns: 1, MaxIdleConns: 1, ConnectTimeout: &short}
	if _, err := OpenControlStore(cfg, ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("short connect timeout error = %v; want deadline exceeded", err)
	}
	cfg.ConnectTimeout = nil
	store, err := OpenControlStore(cfg, "")
	if err != nil {
		t.Fatalf("default connect timeout: %v", err)
	}
	defer store.Close()
}

func TestDatabaseDialectsBindAndInsertIdempotently(t *testing.T) {
	tests := []struct {
		name, driver, bound, insert string
	}{
		{"sqlite", "sqlite", "SELECT ?", "INSERT INTO values_table(id) VALUES(?) ON CONFLICT DO NOTHING"},
		{"postgres", "pgx", "SELECT $1, $2", "INSERT INTO values_table(id) VALUES($1) ON CONFLICT DO NOTHING"},
		{"mysql", "mysql", "SELECT ?, ?", "INSERT IGNORE INTO values_table(id) VALUES(?)"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dialect, err := resolveDatabaseDialect(test.name)
			if err != nil {
				t.Fatal(err)
			}
			query := "SELECT ?"
			if test.name != "sqlite" {
				query = "SELECT ?, ?"
			}
			if got := dialect.Bind(query); got != test.bound {
				t.Fatalf("Bind=%q want=%q", got, test.bound)
			}
			if got := dialect.Bind(dialect.InsertIgnore("INSERT INTO values_table(id) VALUES(?)")); got != test.insert {
				t.Fatalf("InsertIgnore=%q want=%q", got, test.insert)
			}
			if dialect.DriverName() != test.driver {
				t.Fatalf("driver=%q", dialect.DriverName())
			}
		})
	}
	if _, err := resolveDatabaseDialect("legacy"); err == nil {
		t.Fatal("unsupported dialect accepted")
	}
}

func TestAllConfiguredDatabaseDriversAreRegistered(t *testing.T) {
	drivers := sql.Drivers()
	for _, expected := range []string{"sqlite", "pgx", "mysql"} {
		found := false
		for _, driver := range drivers {
			found = found || driver == expected
		}
		if !found {
			t.Fatalf("driver %q not registered; got %v", expected, drivers)
		}
	}
	if reflect.DeepEqual(drivers, []string{}) {
		t.Fatal("no SQL drivers registered")
	}
}
