### Title

Every PHP file hardcodes `mysqli_connect("localhost","root","","myhmsdb")` as the database connection

### Summary

There is no configuration file or environment variable in the project. Every PHP file that needs the database independently calls `mysqli_connect("localhost","root","","myhmsdb")`, which is the MySQL `root` superuser account with no password. The same credentials are also mentioned in the project README. The application cannot be deployed with a non-`root` MySQL user without editing every PHP file.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

Use of Hard-coded Password (CWE-798) / Unprotected Storage of Credentials (CWE-256)

### Affected Code

Every PHP file in the application root contains the same line. Examples:

```php
// func.php:2
$con=mysqli_connect("localhost","root","","myhmsdb");

// func1.php:2
$con=mysqli_connect("localhost","root","","myhmsdb");

// func2.php:2
$con=mysqli_connect("localhost","root","","myhmsdb");

// func3.php:2
$con=mysqli_connect("localhost","root","","myhmsdb");

// newfunc.php:2
$con=mysqli_connect("localhost","root","","myhmsdb");

// admin-panel.php:4
$con=mysqli_connect("localhost","root","","myhmsdb");

// admin-panel1.php:3
$con=mysqli_connect("localhost","root","","myhmsdb");

// doctor-panel.php:3
$con=mysqli_connect("localhost","root","","myhmsdb");

// patientsearch.php includes newfunc.php (line 6)
include("newfunc.php");

// doctorsearch.php includes newfunc.php (line 6)
include("newfunc.php");

// messearch.php includes newfunc.php (line 6)
include("newfunc.php");

// appsearch.php includes func.php (line 6)
include("func.php");

// contact.php:2
$con=mysqli_connect("localhost","root","","myhmsdb");

// prescribe.php includes func1.php (line 2)
include('func1.php');

// search.php:3
$con=mysqli_connect("localhost","root","","myhmsdb");
```

### Root Cause

The application has no configuration abstraction. The credentials are baked into the source code and replicated in every PHP file. The lack of a `config.php`/`.env` makes it impossible to deploy the application in a restricted environment without first editing the source code.

### Steps to Reproduce

1. Confirm the pattern across the project:

```bash
grep -nR 'mysqli_connect("localhost","root"' /Users/thanatos/Documents/CVEs/Hospital-Management-System/*.php
```

```text
/Users/thanatos/Documents/CVEs/Hospital-Management-System/admin-panel.php:4:$con=mysqli_connect("localhost","root","","myhmsdb");
/Users/thanatos/Documents/CVEs/Hospital-Management-System/admin-panel1.php:3:$con=mysqli_connect("localhost","root","","myhmsdb");
...
/Users/thanatos/Documents/CVEs/Hospital-Management-System/contact.php:2:$con=mysqli_connect("localhost","root","","myhmsdb");
/Users/thanatos/Documents/CVEs/Hospital-Management-System/doctor-panel.php:3:$con=mysqli_connect("localhost","root","","myhmsdb");
/Users/thanatos/Documents/CVEs/Hospital-Management-System/func.php:2:$con=mysqli_connect("localhost","root","","myhmsdb");
/Users/thanatos/Documents/CVEs/Hospital-Management-System/func1.php:2:$con=mysqli_connect("localhost","root","","myhmsdb");
/Users/thanatos/Documents/CVEs/Hospital-Management-System/func2.php:2:$con=mysqli_connect("localhost","root","","myhmsdb");
/Users/thanatos/Documents/CVEs/Hospital-Management-System/func3.php:2:$con=mysqli_connect("localhost","root","","myhmsdb");
/Users/thanatos/Documents/CVEs/Hospital-Management-System/newfunc.php:2:$con=mysqli_connect("localhost","root","","myhmsdb");
/Users/thanatos/Documents/CVEs/Hospital-Management-System/prescribe.php:4:$con=mysqli_connect("localhost","root","","myhmsdb");
/Users/thanatos/Documents/CVEs/Hospital-Management-System/search.php:3:$con=mysqli_connect("localhost","root","","myhmsdb");
```

2. Trigger a request to confirm the hardcoded credentials are used at runtime:

```bash
curl -sS -i "$BASE_URL/func.php" \
  --data-urlencode "patsub=1" \
  --data-urlencode "email=ram@gmail.com" \
  --data-urlencode "password2=ram123" | head -10
```

The server-side handler completes the login and issues a 302 redirect, confirming that the hardcoded connection works.

3. Connect to the database directly using the same credentials published in the source code:

```bash
mysql --socket=/tmp/mysql.sock -uroot myhmsdb -e "SELECT user();"
```

```text
root@localhost
```

The `root` superuser account is the live database account for every request.

### Impact

Hardcoded database credentials pose several security and operational risks:

- **Lateral movement**: a source-code disclosure (e.g. through `.git` exposure, a backup leak, or a backup snapshot) gives an attacker a fully privileged MySQL account.
- **No confidentiality boundary**: the credentials are in every PHP file, and the same `root` account is used both for the application and for any other database operations the developer may run.
- **No rotation**: rotating the database password requires editing every PHP file rather than changing a configuration value.
- **Deployment risk**: the application cannot be deployed to a production environment in which `root` is not the application account, because the credentials are not parameterised.

### CVSS 3.1

```
CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
Score: 6.4 (Medium)
```
