---
title: 'MSMS-PHP (by: oretnom23 ) v1.0 - HIT STRIKE!'
author: nu11secur1ty
score: 1
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-09-02T10:38:09.459136'
revision_date: '2021-09-02T16:10:11.130665'
assessment_id: f6d09cc7-459e-442b-be8e-56f16a1598e3
topic_id: 255ad8e4-cffd-4e96-8517-115953336f9e
topic_short_id: FvZ65na3d1
topic_slug: msms-php-by-oretnom23-v1-0---hit-strike
akb_topic_url: https://attackerkb.com/topics/FvZ65na3d1/msms-php-by-oretnom23-v1-0---hit-strike
akb_assessment_url: https://attackerkb.com/topics/FvZ65na3d1/msms-php-by-oretnom23-v1-0---hit-strike#f6d09cc7-459e-442b-be8e-56f16a1598e3
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# MSMS-PHP (by: oretnom23 ) v1.0 - HIT STRIKE!

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/FvZ65na3d1/msms-php-by-oretnom23-v1-0---hit-strike#f6d09cc7-459e-442b-be8e-56f16a1598e3).*

---

## CVE-nu11-05 MSMS-PHP (by: oretnom23 ) v1.0 HIT STRIKE
![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/oretnom23/CVE-nu11-05/docs/Capture.PNG)

### Description:
The MSMS-PHP (by: oretnom23 ) v1.0 is vulnerable in three sections!
- - - remote SQL-Injection-Bypass-Authentication
- m0re info: https://portswigger.net/support/using-sql-injection-to-bypass-authentication. 
The parameter (username) from the login form is not protected correctly and there is no security and escaping from malicious payloads. 
When the user will sending a malicious query or malicious payload to the MySQL server he can bypass the login credentials and take control of the administer account.
- - - XSS - Stored PHPSESSID Vulnerable
- - The vulnerable XSS app: is "brand", parameters: "name" and "description"
After the successful SQL injection, the malicious user can be storing an XSS payload whit who can take the 
active PHPSESSID session.
- - - remote PHPSESSID - Hijacking
- After the successful XSS attack the malicious user can take control of the administrative account of the system from everywhere 
by using the PHPSESSID, and then he can make a lot of bad things!

----------------------------------------------------------------------------------
### Remote vulnerable links execution:
- - - [+] . http://localhost/mobile_store/admin/login.php
- - - [+] . http://localhost/mobile_store/admin/?page=maintenance/brand

----------------------------------------------------------------------------------
## Broken query:
```php
	public function login(){
		extract($_POST);

		$qry = $this->conn->query("SELECT * from users where username = '$username' and password = md5('$password') ");
		if($qry->num_rows > 0){
			foreach($qry->fetch_array() as $k => $v){
				if(!is_numeric($k) && $k != 'password'){
					$this->settings->set_userdata($k,$v);
				}

			}
```
## The fix, but not strong enough!
 
```php
	public function login(){
		extract($_POST);

		$qry = $this->conn->query("SELECT * from users where username = ('$username') and password = md5('$password') ");
		if($qry->num_rows > 0){
			foreach($qry->fetch_array() as $k => $v){
				if(!is_numeric($k) && $k != 'password'){
					$this->settings->set_userdata($k,$v);
				}

			}
```
## Stored XSS payload:
```html
<p class="truncate-1 m-0">alert(document.cookie)</p>
```

## Proof:
- [+] [href](https://streamable.com/c9dyxb)


### CONCLUSION: 
- - - [+] `This vendor must STOP creating all these broken projects and vulnerable software programs, probably he is not a developer!`

### BR 
- [+] @nu11secur1ty System Administrator - Infrastructure and Penetration Testing Engineer
