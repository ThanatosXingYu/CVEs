# EXP Report Index — ponaravindb / Hospital-Management-System

Target: `https://github.com/ponaravindb/Hospital-Management-System`
Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

## Vulnerability Summary

| # | File | Class | Severity | CVSS 3.1 | Title |
|---|------|-------|----------|----------|-------|
| 01 | `func.php`, `func1.php`, `func3.php` | SQL Injection | Critical | 9.1 | SQL injection in `func.php`/`func1.php`/`func3.php` authentication bypasses all logins |
| 02 | `appsearch.php`, `patientsearch.php`, `doctorsearch.php`, `messearch.php` | SQL Injection | High | 7.5 | SQL injection in `appsearch.php`/`patientsearch.php`/`doctorsearch.php`/`messearch.php` leaks patient, doctor, appointment, and message data |
| 03 | `prescribe.php`, `func2.php`, `admin-panel1.php` | SQL Injection | Critical | 9.1 | SQL injection in `prescribe.php`/`func2.php`/`admin-panel1.php` allows arbitrary inserts and database content manipulation |
| 04 | `admin-panel.php`, `doctor-panel.php` | SQL Injection | Critical | 9.4 | SQL injection in appointment cancellation endpoints `admin-panel.php?cancel` and `doctor-panel.php?cancel` |
| 05 | `contact.php`, `admin-panel1.php` | Cross-Site Scripting | Critical | 9.0 | Stored XSS in `contact.php` allows any visitor to run arbitrary JavaScript in the receptionist's browser |
| 06 | `prescribe.php`, `doctor-panel.php`, `admin-panel1.php` | Cross-Site Scripting | Critical | 9.0 | Stored XSS in `prescribe.php` executes arbitrary JavaScript in the dashboards of every doctor and receptionist |
| 07 | `func2.php`, `admin-panel1.php` | Cross-Site Scripting | Critical | 9.0 | Stored XSS in `func2.php` patient registration executes arbitrary JavaScript in the receptionist's browser |
| 08 | `prescribe.php` | Cross-Site Scripting | Critical | 9.0 | Reflected XSS in `prescribe.php` allows arbitrary JavaScript execution via crafted `prescribe.php?fname=...` links |
| 09 | `admin-panel.php`, `admin-panel1.php`, `doctor-panel.php` | Improper Authentication | Critical | 9.8 | `admin-panel.php`, `admin-panel1.php`, and `doctor-panel.php` are reachable without authentication and expose the entire database |
| 10 | `myhmsdb.sql`, `func2.php`, `admin-panel1.php`, `func.php` | Cleartext Storage of Sensitive Information | Medium | 6.0 | All passwords (`patreg`, `doctb`, `admintb`) are stored as plaintext and compared by string equality |
| 11 | `myhmsdb.sql` | Use of Default Credentials | Critical | 9.8 | `myhmsdb.sql` ships a fully-populated user table with weak, identical username/password pairs (e.g. `admin/admin123`, `ashok/ashok123`) |
| 12 | `doctorsearch.php` | Exposure of Sensitive Information Through Data Queries | High | 7.5 | `doctorsearch.php` returns the plaintext password of any doctor in the response |
| 13 | `patientsearch.php` | Exposure of Sensitive Information Through Data Queries | High | 7.5 | `patientsearch.php` returns the plaintext password of any patient in the response |
| 14 | every state-changing endpoint | Cross-Site Request Forgery | High | 8.1 | No CSRF protection on any state-changing endpoint; appointment cancellation is reachable via a GET request |
| 15 | `func.php`, `func1.php`, `func2.php`, `func3.php`, `search.php`, `logout.php`, `logout1.php` | Cookie Without 'HttpOnly' Flag | High | 7.5 | `PHPSESSID` is set without `HttpOnly`, `Secure`, or `SameSite` flags, so the session cookie is readable from JavaScript |
| 16 | every PHP file | Use of Hard-coded Password | Medium | 6.4 | Every PHP file hardcodes `mysqli_connect("localhost","root","","myhmsdb")` as the database connection |
| 17 | `func.php`, `func1.php`, `func3.php` | Improper Restriction of Excessive Authentication Attempts | Critical | 9.1 | Authentication endpoints allow unlimited brute-force attempts; no rate limiting, lockout, or CAPTCHA |
| 18 | `func.php`, `func3.php`, `newfunc.php` | SQL Injection | Critical | 9.1 | SQL injection in the `update_data` payment handler (`func.php`, `func3.php`, `newfunc.php`) |



## Reproduction Environment

- PHP 7.4.33 + nginx (Docker container `baota`, Ubuntu 24.04)
- MySQL 5.7.44 (root password left empty)
- Deployment: `http://hms.localhost/`
- Database: `myhmsdb` (seeded from `myhmsdb.sql`)

All `curl` commands in the individual reports use `BASE_URL="http://hms.localhost"`. SQL sanity checks use:

```bash
mysql --socket=/tmp/mysql.sock -uroot myhmsdb
```

## Outstanding Follow-up

- EXP-18 is latent (the `payment` column does not exist in the current schema). Exploitation becomes trivial if the schema is corrected.
- EXP-09 is the highest-impact because every state-changing endpoint in the application is reachable without authentication. Combined with EXP-01 (login bypass), EXP-05/06/07 (stored XSS), and EXP-15 (non-`HttpOnly` cookie), the entire staff surface is publicly exploitable.
- EXP-10 and EXP-16 are the root causes that enable every other vulnerability in the application; both should be fixed before deploying the codebase.
