### Title

All passwords (`patreg`, `doctb`, `admintb`) are stored as plaintext and compared by string equality

### Summary

The application stores user passwords in cleartext columns of type `varchar(30)` / `varchar(50)`. The very same value is used as the authentication credential (`where password='$password'`). The seed file `myhmsdb.sql` ships pre-hashed-style defaults like `admin123`, `ashok123`, `kishan123`, etc. The plaintext password column is also rendered back to the receptionist UI and to any user who calls the `patientsearch.php`/`doctorsearch.php` endpoints. A database breach therefore reveals every credential in the system.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

Cleartext Storage of Sensitive Information (CWE-312)

### Affected Code

File: `myhmsdb.sql`

```sql
CREATE TABLE `patreg` (
  ...
  `password` varchar(30) NOT NULL,
  `cpassword` varchar(30) NOT NULL
);
CREATE TABLE `doctb` (
  `username` varchar(50) NOT NULL,
  `password` varchar(50) NOT NULL,
  ...
);
CREATE TABLE `admintb` (
  `username` varchar(50) NOT NULL,
  `password` varchar(30) NOT NULL
);

INSERT INTO `admintb` VALUES ('admin', 'admin123');
INSERT INTO `doctb` VALUES ('ashok', 'ashok123', ...);
INSERT INTO `patreg` VALUES ('ram', 'kumar', ..., 'ram123', 'ram123');
```

File: `func2.php`

```php
$password=$_POST['password'];
$cpassword=$_POST['cpassword'];
$query="insert into patreg(fname,lname,gender,email,contact,password,cpassword) values ('$fname','$lname','$gender','$email','$contact','$password','$cpassword');";
```

File: `admin-panel1.php`

```php
$query="insert into doctb(username,password,email,spec,docFees)values('$doctor','$dpassword','$demail','$spec','$docFees')";
```

File: `func.php` (login handler)

```php
$query="select * from patreg where email='$email' and password='$password';";
```

### Root Cause

There is no call to `password_hash()`, `crypt()`, `md5()`, or any other hash function. The cleartext value is written directly into the column and compared directly in the `WHERE` clause.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Inspect the seed credentials to confirm they are stored as plaintext:

```bash
mysql --socket=/tmp/mysql.sock -uroot myhmsdb -e "SELECT username,password FROM admintb;"
```

```text
username  password
admin     admin123
```

```bash
mysql --socket=/tmp/mysql.sock -uroot myhmsdb -e "SELECT username,password FROM doctb LIMIT 5;"
```

```text
username  password
ashok     ashok123
arun      arun123
Dinesh    dinesh123
Ganesh    ganesh123
Kumar     kumar123
```

```bash
mysql --socket=/tmp/mysql.sock -uroot myhmsdb -e "SELECT pid,fname,lname,password,cpassword FROM patreg LIMIT 5;"
```

```text
pid  fname  lname  password    cpassword
1    Ram    Kumar  ram123      ram123
2    Alia   Bhatt  alia123     alia123
3    Shahrukh khan  shahrukh123 shahrukh123
4    Kishan Lal    kishan123    kishan123
5    Gautam Shankararam gautam123 gautam123
```

3. The plaintext password is also surfaced in the receptionist UI: `admin-panel1.php` and `patientsearch.php` both contain `echo "<td>$password</td>"` for the `patreg` table.

```bash
curl -sS "$BASE_URL/patientsearch.php" \
  --data-urlencode "patient_search_submit=1" \
  --data-urlencode "patient_contact=9876543210" \
  | grep -A1 "Password"
```

```html
<th>Password</th>
...
<td>ram123</td>
```

4. Confirm the same value works as the authentication credential:

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

### Impact

Storing passwords in plaintext creates three compounding risks:

- **Database breach**: a single SQL injection (CVE-01 to CVE-04) or backup snapshot leak exposes every patient, doctor, and receptionist credential.
- **Insider threat**: any staff member with read access to the database can harvest credentials.
- **Re-use risk**: the same password is used both for login and rendered back into the receptionist UI, so the cleartext is also disclosed to anyone who can call `patientsearch.php`/`doctorsearch.php` or load the Patient List tab.

### CVSS 3.1

```
CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N
Score: 6.0 (Medium)
```
