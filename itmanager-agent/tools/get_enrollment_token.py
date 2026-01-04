import os
import sys

import pyodbc


def main() -> int:
    server = os.environ.get("ITM_MSSQL_HOST", "192.168.1.32")
    db = os.environ.get("ITM_MSSQL_DB", "itmanager")
    user = os.environ.get("ITM_MSSQL_USER", "sa")
    password = os.environ.get("ITM_MSSQL_PASSWORD", "1453")
    driver = os.environ.get("ITM_MSSQL_DRIVER", "ODBC Driver 18 for SQL Server")

    conn_str = (
        f"DRIVER={{{driver}}};"
        f"SERVER={server};"
        f"DATABASE={db};"
        f"UID={user};PWD={password};"
        "Encrypt=yes;TrustServerCertificate=yes;"
    )

    cn = pyodbc.connect(conn_str, timeout=5)
    cur = cn.cursor()
    cur.execute("SELECT TOP 1 agent_enrollment_token FROM server_config ORDER BY id")
    row = cur.fetchone()
    if not row:
        print("(no server_config row)")
        return 2

    print(row[0])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
