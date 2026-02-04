# Attack Patterns Documentation

This document explains the attack patterns detected by the Log Analysis Dashboard and how they work.

## 1. Brute Force Attacks

### What is it?
A brute force attack is when an attacker tries many different passwords or credentials to gain unauthorized access to an account or system.

### How we detect it
We count failed login attempts (HTTP status codes 401 Unauthorized or 403 Forbidden) from the same IP address. If an IP has 5 or more failed attempts, it's flagged as a potential brute force attack.

### Example from logs
```
192.168.1.50 - - [03/Feb/2026:10:20:01 +0000] "POST /login HTTP/1.1" 401 512
192.168.1.50 - - [03/Feb/2026:10:20:02 +0000] "POST /login HTTP/1.1" 401 512
192.168.1.50 - - [03/Feb/2026:10:20:03 +0000] "POST /login HTTP/1.1" 401 512
192.168.1.50 - - [03/Feb/2026:10:20:04 +0000] "POST /login HTTP/1.1" 401 512
192.168.1.50 - - [03/Feb/2026:10:20:05 +0000] "POST /login HTTP/1.1" 401 512
```

**Detection logic:** 5 failed login attempts from 192.168.1.50 = Brute force attack

### Real-world impact
- Account takeover
- System compromise
- Data breaches

### Mitigation
- Implement rate limiting
- Use CAPTCHA after multiple failed attempts
- Enable multi-factor authentication (MFA)
- Lock accounts temporarily after failed attempts

---

## 2. SQL Injection

### What is it?
SQL injection is when attackers insert malicious SQL code into input fields to manipulate the database and access unauthorized data.

### How we detect it
We scan URLs for common SQL injection patterns:
- `' OR '1'='1`
- `'--` (SQL comment)
- `UNION SELECT`
- `DROP TABLE`
- `1=1`

### Example from logs
```
192.168.1.75 - - [03/Feb/2026:11:30:22 +0000] "GET /search?q=' OR '1'='1 HTTP/1.1" 200 2048
192.168.1.75 - - [03/Feb/2026:11:30:25 +0000] "GET /search?q=admin'-- HTTP/1.1" 200 1500
```

**Detection logic:** URLs contain `' OR '1'='1` pattern = SQL injection attempt

### Real-world impact
- Database compromise
- Data theft (credit cards, passwords, personal info)
- Complete system takeover

### Mitigation
- Use parameterized queries/prepared statements
- Validate and sanitize all user input
- Use an ORM (Object-Relational Mapping) framework
- Apply principle of least privilege for database accounts

---

## 3. Path Traversal (Directory Traversal)

### What is it?
Path traversal attacks attempt to access files and directories outside the web root by using `../` sequences to navigate up the directory tree.

### How we detect it
We look for `../` or `..\` patterns in requested paths.

### Example from logs
```
192.168.1.99 - - [03/Feb/2026:12:45:10 +0000] "GET /files/../../etc/passwd HTTP/1.1" 403 0
192.168.1.99 - - [03/Feb/2026:12:45:12 +0000] "GET /files/../../../windows/system32/config/sam HTTP/1.1" 403 0
```

**Detection logic:** URLs contain `../` trying to access sensitive system files

### Real-world impact
- Access to sensitive configuration files
- Exposure of password files
- System information disclosure

### Mitigation
- Validate and sanitize file paths
- Use allowlists for permitted files
- Implement proper access controls
- Use chroot jails or containers

---

## 4. Scanning/Reconnaissance

### What is it?
Scanning is when attackers probe a website for hidden pages, admin panels, backup files, or configuration files to map the attack surface before launching a targeted attack.

### How we detect it
We count 404 (Not Found) responses from the same IP. If an IP receives 5 or more 404s, it indicates they're searching for hidden resources.

### Example from logs
```
192.168.1.120 - - [03/Feb/2026:14:00:01 +0000] "GET /admin HTTP/1.1" 404 128
192.168.1.120 - - [03/Feb/2026:14:00:02 +0000] "GET /backup HTTP/1.1" 404 128
192.168.1.120 - - [03/Feb/2026:14:00:03 +0000] "GET /config HTTP/1.1" 404 128
192.168.1.120 - - [03/Feb/2026:14:00:04 +0000] "GET /test HTTP/1.1" 404 128
192.168.1.120 - - [03/Feb/2026:14:00:05 +0000] "GET /phpMyAdmin HTTP/1.1" 404 128
```

**Detection logic:** 5+ different 404 responses from same IP = Scanning activity

### Real-world impact
- Information gathering for future attacks
- Discovery of vulnerable endpoints
- Mapping of application structure

### Mitigation
- Implement rate limiting
- Use Web Application Firewall (WAF)
- Monitor and block suspicious IPs
- Return generic error pages (don't reveal system info)

---

## Detection Thresholds

Our tool uses these thresholds (configurable in the code):

- **Brute Force**: 5+ failed login attempts
- **Scanning**: 5+ pages returning 404 errors
- **SQL Injection**: Any detected pattern
- **Path Traversal**: Any detected pattern

These thresholds balance between catching real attacks and avoiding false positives from legitimate user behavior.

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)