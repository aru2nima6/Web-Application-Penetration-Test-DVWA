# Web-Application-Penetration-Test-DVWA

## What is DVWA?
DVWA (Damn Vulnerable Web Application) is a deliberately 
insecure web application designed for security professionals 
to practice identifying and exploiting common web vulnerabilities 
in a legal, controlled environment.

## Environment
| | Details |
|---|---|
| Platform | DVWA running on Kali Linux (localhost) |
| Web Server | Apache2 |
| Database | MariaDB |
| Security Level | Low (intentional — focus on technique) |
| Tools Used | Firefox Browser, DVWA interface, manual testing |

## Findings Summary

| # | Vulnerability | Severity | OWASP 2021 Category |
|---|---|---|---|
| 1 | SQL Injection | High | A03 — Injection |
| 2 | XSS Reflected | Medium | A03 — Injection |
| 3 | XSS Stored | High | A03 — Injection |
| 4 | IDOR | Medium | A01 — Broken Access Control |

---

## Finding 1: SQL Injection

**Location:** /dvwa/vulnerabilities/sqli/

**Severity:** High

**OWASP:** A03:2021 — Injection

### What is it?
SQL Injection happens when user input is inserted directly 
into a database query without sanitisation. An attacker can 
manipulate the query logic to extract data that was never 
meant to be accessible.

### How I found it
Entered a normal User ID (1) — got expected output.
Then entered:

1' OR ‘1’='1

This caused the application to return ALL users instead 
of just user 1 — confirming the input was being passed 
directly into the SQL query.

Then used a UNION SELECT payload to extract 
usernames and password hashes:

1' UNION SELECT user, password FROM users-- -


### Evidence
![Normal output](screenshots/sqli_01_normal_output.png)
![OR payload — all users returned](screenshots/sqli_02_or_payload.png)
![UNION SELECT — password hashes extracted](screenshots/sqli_03_union_hashes.png)

### Impact
An attacker could extract all usernames and hashed passwords 
from the database, potentially compromising every user account 
on the application.

### Remediation
Use parameterised queries (prepared statements):
```php
// Vulnerable:
$query = "SELECT * FROM users WHERE id = '$id'";

// Fixed:
$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("s", $id);
```

---

## Finding 2: Cross-Site Scripting — Reflected (XSS)

**Location:** /dvwa/vulnerabilities/xss_r/
**Severity:** Medium
**OWASP:** A03:2021 — Injection

### What is it?
Reflected XSS occurs when user input is immediately returned 
by the server in the page response without sanitisation, 
causing the browser to execute injected JavaScript.

### How I found it
Typed a normal name — got "Hello [name]" response.
Then injected:
```html
<script>alert('XSS')</script>
```
The browser executed the script and showed an alert box — 
confirming the input was reflected directly into the HTML.

Then tested cookie theft simulation:
```html
<script>alert(document.cookie)</script>
```
The page's session cookie was displayed in the alert.

### Evidence
![Normal response](screenshots/xss_reflected_01_normal.png)
![Alert box executing](screenshots/xss_reflected_02_alert.png)
![Cookie displayed](screenshots/xss_reflected_03_cookie.png)

### Impact
An attacker could craft a malicious URL containing the 
script payload and trick a victim into clicking it. 
The victim's session cookie would be sent to the attacker, 
enabling session hijacking without needing credentials.

### Remediation
Encode all user output before rendering in HTML:
```php
// Vulnerable:
echo "Hello " . $_GET['name'];

// Fixed:
echo "Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES);
```

---

## Finding 3: Cross-Site Scripting — Stored (XSS)

**Location:** /dvwa/vulnerabilities/xss_s/
**Severity:** High
**OWASP:** A03:2021 — Injection

### What is it?
Stored XSS is more dangerous than reflected XSS because 
the malicious script is saved to the database and executes 
for every user who views the affected page — not just the 
person who submitted the payload.

### How I found it
Submitted this payload in the guestbook message field:
```html
<script>alert('Stored XSS')</script>
```
Every time the page loaded — including for any other user 
viewing the guestbook — the alert fired automatically.

### Evidence
![Payload submitted](screenshots/xss_stored_01_payload.png)
![Alert fires on page load](screenshots/xss_stored_02_alert_fires.png)

### Impact
One injection affects every visitor to the page indefinitely 
until the database entry is removed. A real attacker could 
inject a script that silently exfiltrates every visitor's 
session cookie to an external server.

### Key difference from Reflected XSS
| | Reflected | Stored |
|---|---|---|
| Where payload lives | In the URL | In the database |
| Who is affected | One user per click | Every visitor |
| Persistence | None | Until record deleted |

### Remediation
Same as reflected XSS — output encoding plus input 
validation before storing to database.

---

## Finding 4: Insecure Direct Object Reference (IDOR)

**Location:** /dvwa/vulnerabilities/sqli/ (URL parameter)
**Severity:** Medium
**OWASP:** A01:2021 — Broken Access Control

### What is it?
IDOR occurs when an application uses user-controllable 
input to access objects directly without verifying whether 
the requesting user has permission to access that specific 
resource.

### How I found it
Normal request URL:

http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit

Changed id=1 to id=2, id=3, id=4 — each returned a 
different user's data with no authorisation check.
Any user ID is accessible by simply changing the number.

### Evidence
![Normal URL — id=1](screenshots/idor_01_normal_url.png)
![Changed to id=2 — different user's data](screenshots/idor_02_changed_url.png)

### Impact
Any user can access any other user's data just by 
incrementing a number in the URL. In a real application 
this could expose personal information, financial records, 
or private messages of every user.

### Remediation
Implement server-side authorisation checks:
```php
// Check that the requested resource belongs 
// to the currently logged-in user before returning it
if ($requested_user_id !== $session_user_id) {
    die("Access denied");
}
```

---

## Key Takeaways

**1. Never trust user input**
Every single finding in this assessment came from the 
application trusting user-supplied data. Validate, 
sanitise, and encode everything.

**2. Parameterised queries prevent SQL Injection entirely**
Not "reduce the risk" — prevent it entirely. There is 
no excuse for SQL Injection in modern applications.

**3. Output encoding prevents XSS**
Never reflect user input directly into HTML. 
`htmlspecialchars()` in PHP, equivalent functions in 
every other language.

**4. Authorisation must be checked server-side**
The client (browser) cannot be trusted to enforce access 
controls. Every data request must be verified on the server 
against the authenticated user's permissions.

**5. Stored XSS is significantly more dangerous than Reflected**
Reflected XSS requires tricking one user per attack. 
Stored XSS compromises every visitor automatically and 
indefinitely — one injection, unlimited victims.

---

*All testing conducted on DVWA running locally on Kali Linux. 
No real systems or users were affected.*
