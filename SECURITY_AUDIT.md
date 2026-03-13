# Security Vulnerability Audit Report

**Application**: TicketsCAD v3.43.0
**Date**: 2026-03-13
**Scope**: SQL Injection (CWE-89) and Directory Traversal (CWE-22)
**Overall Risk Level**: CRITICAL

---

## Executive Summary

This audit identified **20+ SQL Injection vulnerabilities** and **6 Directory Traversal vulnerabilities** across the TicketsCAD codebase. The application is a legacy PHP/MySQL dispatch management system with ~808 PHP files. It uses deprecated `mysql_*` functions (wrapped via a compatibility layer), constructs queries via string concatenation, and performs file operations with unsanitized user input. Many of these issues are trivially exploitable and could lead to full database compromise or arbitrary file access on the server.

---

## Part 1: SQL Injection Vulnerabilities

### VULN-SQL-01 — Direct `$_GET` injection in patient records [CRITICAL]

| Field | Value |
|-------|-------|
| **File** | `patient.php` |
| **Lines** | 304, 324, 331, 357, 365, 369, 372, 376, 379 |

Multiple `$_GET` parameters (`ticket_id`, `id`) are concatenated directly into SQL queries without any escaping:

```php
// Line 304
mysql_query("UPDATE ... WHERE id='$_GET[ticket_id]' LIMIT 1")

// Line 324
$query = "DELETE FROM ... WHERE `id`='$_GET[id]' LIMIT 1";

// Line 372
mysql_query("SELECT ticket_id FROM ... WHERE id='$_GET[id]'")

// Line 376
$query = "SELECT * FROM ... WHERE `patient_id` = " . $_GET['id'];
```

**Impact**: An attacker can read, modify, or delete any patient record or perform UNION-based extraction of the entire database.

---

### VULN-SQL-02 — `strip_tags()` used as SQL escaping [CRITICAL]

| Field | Value |
|-------|-------|
| **File** | `portal/ajax/decline.php` |
| **Lines** | 31, 51 |

```php
$query = "SELECT * FROM ... WHERE `id` = " . strip_tags($_GET['id']) . " LIMIT 1";
$query = "UPDATE ... WHERE `id` = " . strip_tags($_GET['id']);
```

`strip_tags()` only removes HTML tags — it does **not** prevent SQL injection. Input like `1 OR 1=1` passes through untouched.

**Impact**: Full read/write access to the `requests` table; potential database takeover.

---

### VULN-SQL-03 — Mass unescaped `$_GET` in INSERT statement [CRITICAL]

| Field | Value |
|-------|-------|
| **File** | `portal/ajax/insert_request.php` |
| **Lines** | 46–80 |

Over 15 GET parameters are assigned directly to variables and used in an INSERT query with no escaping:

```php
$scope = $_GET['frm_scope'];
$comments = $_GET['frm_comments'];
$street = $_GET['frm_street'];
$city = $_GET['frm_city'];
// ... all used directly in INSERT INTO query
```

**Impact**: Arbitrary data injection; potential stored XSS via injected content.

---

### VULN-SQL-04 — `extract($_GET)` and `extract($_POST)` [CRITICAL]

| Field | Value |
|-------|-------|
| **File** | `maj_inc.php` |
| **Lines** | 19–20 |

```php
extract($_GET);
extract($_POST);
```

`extract()` imports all GET/POST keys as PHP variables, allowing an attacker to overwrite any variable in scope — including database connection parameters, query strings, or session data.

**Impact**: Variable pollution enabling second-order injection, authentication bypass, or arbitrary code paths.

---

### VULN-SQL-05 — Unescaped `$_POST` in DELETE/SELECT [CRITICAL]

| Field | Value |
|-------|-------|
| **File** | `maj_inc.php` |
| **Lines** | Multiple |

```php
$query = "DELETE FROM ... WHERE `id`=" . $_POST['frm_id'];
$query = "SELECT * FROM ... WHERE `id` = " . $_POST['frm_id'];
```

**Impact**: Arbitrary record deletion; database enumeration.

---

### VULN-SQL-06 — Database schema enumeration via `$_POST` [CRITICAL]

| Field | Value |
|-------|-------|
| **File** | `db_loader.php` |
| **Line** | 678 |

```php
$query = "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = '" . $_POST['ticketsdb'] . "';";
```

**Impact**: Enumerate all tables in any database on the server; pivot to data extraction via UNION injection.

---

### VULN-SQL-07 — Unescaped `$_GET` in action records [CRITICAL]

| Field | Value |
|-------|-------|
| **Files** | `action.php`, `action_w.php` |
| **Lines** | action.php:419,454–456; action_w.php:277,321–323 |

```php
mysql_query("DELETE FROM ... WHERE `id`='$_GET[id]' LIMIT 1")
mysql_query("UPDATE ... SET ... WHERE `id`='$_GET[id]'")
```

**Impact**: Delete or modify any action record in the system.

---

### VULN-SQL-08 — Unescaped `$_GET` in patient (wide-layout) [CRITICAL]

| Field | Value |
|-------|-------|
| **File** | `patient_w.php` |
| **Lines** | 287, 381 |

Same pattern as VULN-SQL-01 but in the wide-layout version of the patient page.

---

### VULN-SQL-09 — Unescaped `$_POST` in unit management [CRITICAL]

| Field | Value |
|-------|-------|
| **File** | `units.php` |

```php
$query = "DELETE FROM ... WHERE `id`=" . $_POST['frm_id'];
$query = "SELECT ... WHERE `id` = {$_POST['frm_facility_sel']} LIMIT 1";
```

**Impact**: Delete any responder record; enumerate facility data.

---

### VULN-SQL-10 — ORDER BY injection in search [HIGH]

| Field | Value |
|-------|-------|
| **Files** | `search.php`, `mdb_search.php` |
| **Lines** | search.php:193; mdb_search.php:129,177,223,270,318,361 |

```php
$query = "SELECT ... ORDER BY `" . $_POST['frm_ordertype'] . "` " . $desc;
```

ORDER BY injection can be leveraged for boolean-based blind SQL injection to extract data one bit at a time.

**Impact**: Blind data extraction from the database.

---

### VULN-SQL-11 — Numeric injection in ICS forms [HIGH]

| Field | Value |
|-------|-------|
| **Files** | `ics/ics214a.php`, `ics/ics202.php`, `ics/ics206.php`, `ics/ics221.php`, `ics/ics213.php`, `ics/ics205a.php`, `ics/ics213rr.php`, `ics/ics205.php`, `ics/ics214.php` |

```php
$query = "SELECT ... WHERE `id` = {$_POST['id']} LIMIT 1";
```

Repeated across 9 ICS form files, each with 2 instances.

**Impact**: Read/modify ICS form data.

---

### VULN-SQL-12 — Unescaped `$_POST` in landmark/banner/circle [HIGH]

| Field | Value |
|-------|-------|
| **Files** | `landb.php`, `banner.php`, `circle.php` |

```php
$query = "SELECT ... WHERE `id` = {$_POST['id']}";
```

**Impact**: Read arbitrary records from multiple tables.

---

### VULN-SQL-13 — Unescaped `$_GET` in unit tracking [HIGH]

| Field | Value |
|-------|-------|
| **File** | `track_u.php` |
| **Line** | 28 |

```php
$query = "SELECT * FROM ... WHERE `id` = {$_GET['unit_id']} LIMIT 1;";
```

---

### VULN-SQL-14 — Unescaped `$_GET` in mail editing [HIGH]

| Field | Value |
|-------|-------|
| **File** | `mail_edit.php` |
| **Line** | 19 |

```php
$query = "SELECT ... WHERE `id` = {$_GET['ticket_id']} LIMIT 1";
```

---

### VULN-SQL-15 — Unescaped `$_POST` in resource assignment [HIGH]

| Field | Value |
|-------|-------|
| **File** | `assign_res.php` |
| **Line** | 32 |

```php
$query = "SELECT * FROM ... WHERE `id` = {$_POST['frm_id']} LIMIT 1";
```

---

### VULN-SQL-16 — Field-name injection via POST [HIGH]

| Field | Value |
|-------|-------|
| **File** | `os_watch.php` |
| **Line** | 422 |

```php
$query = "UPDATE ... SET `{$field_name[$_POST['frm_add_to']]}`= CONCAT(...)";
```

The field name is derived from user-controlled array index. If the mapping array doesn't whitelist values, arbitrary column names can be injected.

---

## Part 2: Directory Traversal Vulnerabilities

### VULN-DT-01 — Arbitrary file read via download endpoint [CRITICAL]

| Field | Value |
|-------|-------|
| **File** | `ajax/download.php` |
| **Lines** | 7–16 |

```php
$filename = "../files/" . $_GET['filename'];
readfile("$filename");
```

No validation whatsoever. An attacker can supply `filename=../../../../etc/passwd` to read any file on the server accessible to the web process.

**Impact**: Read arbitrary server files including configuration, database credentials, source code, `/etc/passwd`, etc.

---

### VULN-DT-02 — Arbitrary file read via portal download [CRITICAL]

| Field | Value |
|-------|-------|
| **File** | `portal/ajax/download.php` |
| **Lines** | 7–13 |

```php
$filename = "../../files/" . $_GET['filename'];
readfile("$filename");
```

Identical vulnerability in the portal-facing download endpoint.

**Impact**: Same as VULN-DT-01, accessible from the service user portal.

---

### VULN-DT-03 — Path traversal in PDF reader [CRITICAL]

| Field | Value |
|-------|-------|
| **File** | `read_pdf.php` |
| **Lines** | 2–13 |

```php
$file = $_GET['file'];
$pdf = new PdfToText("$file.pdf");
output($pdf->Text);
```

User-controlled file path with `.pdf` appended. Traversal is still possible (e.g., `../../etc/passwd%00` on older PHP, or targeting any `.pdf` file on the system).

**Impact**: Read contents of arbitrary PDF files on the server; potential information disclosure.

---

### VULN-DT-04 — Arbitrary file deletion via archive handler [HIGH]

| Field | Value |
|-------|-------|
| **File** | `msg_archive.php` |
| **Lines** | 215–219 |

```php
foreach($_POST['files'] as $val) {
    unlink($dir . $val);
}
```

The `$val` from `$_POST['files']` is used directly in `unlink()`. An attacker can supply `../../../important_file` to delete arbitrary files.

**Impact**: Delete arbitrary files on the server, potentially causing denial of service or destroying evidence.

---

### VULN-DT-05 — Path traversal in tile deletion [HIGH]

| Field | Value |
|-------|-------|
| **File** | `ajax/deltile.php` |
| **Lines** | 42–48 |

```php
$zoom = $_GET['zoom'];
$col = $_GET['col'];
$tile = $_GET['tile'];
$file = $filestore . $zoom . "/" . $col . "/" . $tile;
unlink($file);
```

All three path components (`zoom`, `col`, `tile`) are user-controlled without sanitization.

**Impact**: Delete arbitrary files via path traversal.

---

### VULN-DT-06 — Path traversal in tile download [MEDIUM]

| Field | Value |
|-------|-------|
| **File** | `ajax/gettiles.php` |
| **Lines** | 10–12, 41–48 |

```php
$dir = $_GET['dir'];
$subdir = $_GET['subdir'];
$file = $_GET['file'];
$my_addr = "{$local}/{$dir}/{$subdir}/{$file}.png";
```

All path components come from GET parameters without validation.

**Impact**: Read arbitrary `.png` files on the server.

---

## Part 3: Additional Security Concerns

| Issue | Severity | Notes |
|-------|----------|-------|
| **MD5 password hashing** | HIGH | `login.inc.php` uses MD5 — trivially crackable with modern hardware |
| **Deprecated `mysql_*` API** | HIGH | No support for prepared statements; entire DB layer is vulnerable |
| **`stripslashes_deep()` pattern** | MEDIUM | Unreliable defense; assumes magic_quotes behavior |
| **`addslashes()` for SQL** | MEDIUM | Not encoding-aware; bypassable on certain character sets (e.g., GBK) |

---

## Part 4: Mitigation Strategy

### Immediate Actions (Critical — Do Now)

#### 1. Patch the Directory Traversal Endpoints

Add path validation to all file-serving endpoints. At minimum:

```php
// Example fix for ajax/download.php
$allowed_dir = realpath(__DIR__ . '/../files');
$filename = realpath($allowed_dir . '/' . basename($_GET['filename']));

if ($filename === false || strpos($filename, $allowed_dir) !== 0) {
    http_response_code(403);
    exit('Access denied');
}

readfile($filename);
```

Apply the same pattern to:
- `ajax/download.php`
- `portal/ajax/download.php`
- `read_pdf.php`
- `msg_archive.php` (for `unlink()`)
- `ajax/deltile.php` (for `unlink()`)
- `ajax/gettiles.php`

#### 2. Remove `extract()` Calls

In `maj_inc.php`, replace:
```php
extract($_GET);
extract($_POST);
```
with explicit variable assignments for each expected parameter.

#### 3. Sanitize Integer IDs Immediately

For all queries that use IDs from `$_GET`/`$_POST`, cast to integer:
```php
$id = intval($_GET['id']);
$query = "SELECT * FROM ... WHERE `id` = {$id} LIMIT 1";
```

This is a stopgap — parameterized queries are the proper fix (see below).

#### 4. Replace `strip_tags()` in SQL Context

In `portal/ajax/decline.php`, replace `strip_tags($_GET['id'])` with `intval($_GET['id'])`.

### Short-Term Actions (High — Within 2 Weeks)

#### 5. Create a Central Query Builder / Escaping Layer

Add a helper function that enforces escaping:
```php
function safe_query($query, $params = []) {
    global $conn; // MySQLi connection
    $stmt = $conn->prepare($query);
    if ($params) {
        $types = str_repeat('s', count($params));
        $stmt->bind_param($types, ...$params);
    }
    $stmt->execute();
    return $stmt->get_result();
}
```

#### 6. Whitelist ORDER BY Columns

In `search.php` and `mdb_search.php`:
```php
$allowed_columns = ['id', 'date', 'scope', 'status', 'priority'];
$orderBy = in_array($_POST['frm_ordertype'], $allowed_columns)
    ? $_POST['frm_ordertype']
    : 'id';
```

#### 7. Audit File Upload Handling

In `file_upload.php`, ensure:
- The original filename is escaped before use in SQL
- Uploaded files are stored with generated names (already partially done)
- File extension whitelisting is enforced

### Medium-Term Actions (Within 1–3 Months)

#### 8. Migrate from `mysql_*` to MySQLi/PDO with Prepared Statements

The `mysql2i.class.php` compatibility wrapper should be phased out. Convert all queries to use prepared statements:

```php
// Before (vulnerable)
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = mysql_query($query);

// After (safe)
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
$result = $stmt->get_result();
```

Priority order for migration:
1. Files with CRITICAL vulnerabilities (patient.php, portal/ajax/*, action.php, maj_inc.php)
2. Files with HIGH vulnerabilities (search.php, units.php, ICS forms)
3. Remaining files

#### 9. Upgrade Password Hashing

Replace MD5 with `password_hash()` / `password_verify()`:
```php
// Storing
$hash = password_hash($password, PASSWORD_DEFAULT);

// Verifying
if (password_verify($input, $stored_hash)) { ... }
```

#### 10. Implement Input Validation Layer

Add a centralized input validation/sanitization library:
- Type coercion for numeric parameters
- Length limits for string parameters
- Whitelist validation for enumerated values
- CSRF token verification on all state-changing endpoints

### Long-Term Actions (3–6 Months)

#### 11. Adopt a Modern Framework or Templating Engine

The procedural PHP architecture makes security enforcement difficult. Consider:
- Adopting a lightweight framework (e.g., Slim) for routing and middleware
- Using a template engine (e.g., Twig) to prevent XSS
- Implementing middleware-based authentication and authorization

#### 12. Implement Automated Security Testing

- Add static analysis (e.g., PHPStan, Psalm with security rules)
- Add SAST scanning in CI/CD pipeline
- Run OWASP ZAP or similar DAST tool against staging

---

## Summary of Findings

| Category | Critical | High | Medium | Total |
|----------|----------|------|--------|-------|
| SQL Injection | 9 | 7 | 2 | 18 |
| Directory Traversal | 3 | 2 | 1 | 6 |
| Other | 0 | 2 | 2 | 4 |
| **Total** | **12** | **11** | **5** | **28** |

**Files with most vulnerabilities**: `patient.php` (9 instances), `portal/ajax/insert_request.php` (15+ unescaped params), `maj_inc.php` (extract + unescaped queries), `ajax/download.php` (unrestricted file read)

---

*End of Security Audit Report*
