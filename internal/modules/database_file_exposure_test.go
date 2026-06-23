package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dropalldatabases/sif/internal/modules"
)

func runDBFileModule(t *testing.T, file string, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule(file)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	res, err := modules.ExecuteHTTPModule(context.Background(), srv.URL, def, modules.Options{
		Timeout: 5 * time.Second,
		Threads: 2,
	})
	if err != nil {
		t.Fatalf("execute %s: %v", file, err)
	}
	return res
}

func dbFileExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestDatabaseFileExposureModules(t *testing.T) {
	const sqlDump = "../../modules/recon/sql-dump-exposure.yaml"
	const sqlite = "../../modules/recon/sqlite-database-exposure.yaml"
	const redis = "../../modules/recon/redis-dump-exposure.yaml"

	mysqldump := "-- MySQL dump 10.13  Distrib 8.0.32, for Linux (x86_64)\n--\n" +
		"-- Host: localhost    Database: appdb\n--\n-- Server version\t8.0.32\n\n" +
		"DROP TABLE IF EXISTS `users`;\nCREATE TABLE `users` (\n" +
		"  `id` int NOT NULL AUTO_INCREMENT,\n  `email` varchar(255) DEFAULT NULL,\n" +
		"  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n" +
		"INSERT INTO `users` VALUES (1,'admin@x.com');\n"

	pgdump := "--\n-- PostgreSQL database dump\n--\n\nSET statement_timeout = 0;\n" +
		"CREATE TABLE public.accounts (\n    id integer NOT NULL,\n    email text\n);\n" +
		"COPY public.accounts (id, email) FROM stdin;\n1\tadmin@x.com\n\\.\n"

	sqliteFile := "SQLite format 3\x00" + strings.Repeat("\x00", 84) +
		"\x05\x00CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password TEXT)\x00"

	redisDump := "REDIS0011\xfa\x09redis-ver\x055.0.7\xfa\x0aredis-bits\xc0@\xfe\x00\xfb\x02\x00" +
		"\x03key\x05value\xff\x00\x00\x00\x00\x00\x00\x00\x00"

	t.Run("a mysqldump leaks the dumped table", func(t *testing.T) {
		res := runDBFileModule(t, sqlDump, 200, mysqldump)
		if len(res.Findings) == 0 {
			t.Fatal("expected a sql dump finding")
		}
		if v := dbFileExtract(res, "dump_table"); v != "users" {
			t.Errorf("dump_table=%q, want users", v)
		}
	})

	t.Run("a postgresql dump also matches and names its table", func(t *testing.T) {
		res := runDBFileModule(t, sqlDump, 200, pgdump)
		if len(res.Findings) == 0 {
			t.Fatal("expected a sql dump finding for pg_dump")
		}
		if v := dbFileExtract(res, "dump_table"); v != "accounts" {
			t.Errorf("dump_table=%q, want accounts", v)
		}
	})

	t.Run("a sqlite database file leaks its schema table", func(t *testing.T) {
		res := runDBFileModule(t, sqlite, 200, sqliteFile)
		if len(res.Findings) == 0 {
			t.Fatal("expected a sqlite finding")
		}
		if v := dbFileExtract(res, "table_name"); v != "users" {
			t.Errorf("table_name=%q, want users", v)
		}
	})

	t.Run("a redis rdb snapshot leaks its format version", func(t *testing.T) {
		res := runDBFileModule(t, redis, 200, redisDump)
		if len(res.Findings) == 0 {
			t.Fatal("expected a redis rdb finding")
		}
		if v := dbFileExtract(res, "rdb_version"); v != "0011" {
			t.Errorf("rdb_version=%q, want 0011", v)
		}
	})

	t.Run("sql shown inside an html page is not a dump", func(t *testing.T) {
		body := "<!DOCTYPE html><html><head><title>SQL tutorial</title></head><body>" +
			"<pre>DROP TABLE IF EXISTS users; CREATE TABLE users (id int); INSERT INTO users VALUES (1);</pre>" +
			"</body></html>"
		if res := runDBFileModule(t, sqlDump, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html tutorial should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a sql file with no dump idiom is not flagged", func(t *testing.T) {
		body := "-- migration notes\nSELECT id FROM users WHERE active = 1;\n"
		if res := runDBFileModule(t, sqlDump, 200, body); len(res.Findings) > 0 {
			t.Errorf("a bare select should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a page that names the sqlite format is not the file", func(t *testing.T) {
		body := "This page documents the SQLite format 3 on-disk structure for readers."
		if res := runDBFileModule(t, sqlite, 200, body); len(res.Findings) > 0 {
			t.Errorf("prose about sqlite should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a page that names redis is not an rdb snapshot", func(t *testing.T) {
		body := "redis-server is running on this host as the REDIS cache backend."
		if res := runDBFileModule(t, redis, 200, body); len(res.Findings) > 0 {
			t.Errorf("prose about redis should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("the sqlite magic only counts at the start of the file", func(t *testing.T) {
		body := "<pre>hexdump of a header: " + sqliteFile + "</pre>"
		if res := runDBFileModule(t, sqlite, 200, body); len(res.Findings) > 0 {
			t.Errorf("an embedded sqlite header should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("the rdb magic only counts at the start of the file", func(t *testing.T) {
		body := "log line: loaded snapshot " + redisDump
		if res := runDBFileModule(t, redis, 200, body); len(res.Findings) > 0 {
			t.Errorf("an embedded rdb header should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{sqlDump, sqlite, redis} {
			if res := runDBFileModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{sqlDump, sqlite, redis} {
			if res := runDBFileModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
