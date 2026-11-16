package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	readOnly = os.Getenv("ZS_CLIENT_ACCESS") == "read_only"
	table    = os.Getenv("ZS_CLIENT_TABLE")
	mode     = regexp.MustCompile(`(?i)read[-_ ]only`)
	failed   = false
)

func writeStep(step string, err error) {
	var pg *pgconn.PgError
	switch {
	case readOnly && errors.As(err, &pg) && mode.MatchString(pg.Message):
		fmt.Printf("%s: refused %s %s\n", step, pg.Code, pg.Message)
	case !readOnly && err == nil:
		fmt.Printf("%s: ok\n", step)
	default:
		fmt.Printf("%s: FAIL %v\n", step, err)
		failed = true
	}
}

func readStep(ctx context.Context, conn *pgx.Conn, step string, expected int64) {
	var rows int64
	err := conn.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&rows)
	if err == nil && rows == expected {
		fmt.Printf("%s: ok rows=%d\n", step, rows)
		return
	}
	fmt.Printf("%s: FAIL rows=%d err=%v\n", step, rows, err)
	failed = true
}

func main() {
	ctx := context.Background()
	target := strings.Join([]string{
		"host=" + os.Getenv("ZS_CLIENT_HOST"),
		"port=" + os.Getenv("ZS_CLIENT_PORT"),
		"user=" + os.Getenv("ZS_CLIENT_USER"),
		"dbname=" + os.Getenv("ZS_CLIENT_DB"),
		"sslmode=disable",
	}, " ")
	conn, err := pgx.Connect(ctx, target)
	if err != nil {
		fmt.Printf("connect: FAIL %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(ctx)

	readStep(ctx, conn, "read", 1)
	_, err = conn.Exec(ctx, "INSERT INTO "+table+" VALUES (2)")
	writeStep("write", err)
	_, err = conn.Exec(ctx, "SET default_transaction_read_only = off")
	writeStep("switch-off", err)
	_, err = conn.Exec(ctx, "INSERT INTO "+table+" VALUES (3)")
	writeStep("write-after-switch-off", err)
	if readOnly {
		readStep(ctx, conn, "read-after", 1)
	} else {
		readStep(ctx, conn, "read-after", 3)
	}
	if failed {
		os.Exit(1)
	}
}
