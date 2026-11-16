import os
import sys

import psycopg

table = os.environ["ZS_CLIENT_TABLE"]
read_only = os.environ["ZS_CLIENT_ACCESS"] == "read_only"
failed = False


def attempt(conn, sql):
    try:
        cur = conn.execute(sql)
        return True, cur.fetchone() if cur.description else None, None, None
    except psycopg.Error as error:
        return False, None, error.sqlstate, str(error).splitlines()[0]


def write_step(step, outcome):
    global failed
    ok, _, code, message = outcome
    if read_only and not ok and code == "25006" and "read" in message.lower() and "only" in message.lower():
        print(f"{step}: refused {code} {message}")
    elif not read_only and ok:
        print(f"{step}: ok")
    else:
        print(f"{step}: FAIL {'succeeded' if ok else message}")
        failed = True


def read_step(step, outcome, expected):
    global failed
    ok, row, _, message = outcome
    if ok and row[0] == expected:
        print(f"{step}: ok rows={row[0]}")
    else:
        print(f"{step}: FAIL rows={row if ok else message}")
        failed = True


conn = psycopg.connect(
    host=os.environ["ZS_CLIENT_HOST"],
    port=int(os.environ["ZS_CLIENT_PORT"]),
    user=os.environ["ZS_CLIENT_USER"],
    dbname=os.environ["ZS_CLIENT_DB"],
    sslmode="disable",
    autocommit=True,
)
read_step("read", attempt(conn, f"SELECT count(*) FROM {table}"), 1)
write_step("write", attempt(conn, f"INSERT INTO {table} VALUES (2)"))
write_step("switch-off", attempt(conn, "SET default_transaction_read_only = off"))
write_step("write-after-switch-off", attempt(conn, f"INSERT INTO {table} VALUES (3)"))
read_step("read-after", attempt(conn, f"SELECT count(*) FROM {table}"), 1 if read_only else 3)
conn.close()
sys.exit(1 if failed else 0)
