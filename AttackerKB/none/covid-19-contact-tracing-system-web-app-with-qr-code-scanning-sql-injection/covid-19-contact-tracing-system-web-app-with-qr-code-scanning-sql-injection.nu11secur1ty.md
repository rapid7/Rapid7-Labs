---
title: 'Covid-19 Contact Tracing System Web App with QR Code Scanning - SQL-Injection-Bypass-Authentication '
author: nu11secur1ty
score: 1
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-08-31T14:17:32.594398'
revision_date: '2021-09-01T16:44:50.274348'
assessment_id: 2e3e8e38-bd54-47c7-b368-958921dbd37a
topic_id: 934c6033-0c6f-4e2c-a428-9379aff6ad2f
topic_short_id: qDyKFbUlOm
topic_slug: covid-19-contact-tracing-system-web-app-with-qr-code-scanning---sql-injection-bypass-authentication
akb_topic_url: https://attackerkb.com/topics/qDyKFbUlOm/covid-19-contact-tracing-system-web-app-with-qr-code-scanning---sql-injection-bypass-authentication
akb_assessment_url: https://attackerkb.com/topics/qDyKFbUlOm/covid-19-contact-tracing-system-web-app-with-qr-code-scanning---sql-injection-bypass-authentication#2e3e8e38-bd54-47c7-b368-958921dbd37a
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# Covid-19 Contact Tracing System Web App with QR Code Scanning - SQL-Injection-Bypass-Authentication 

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/qDyKFbUlOm/covid-19-contact-tracing-system-web-app-with-qr-code-scanning---sql-injection-bypass-authentication#2e3e8e38-bd54-47c7-b368-958921dbd37a).*

---

# CVE-nu11-04
## Covid-19 Contact Tracing System Web App with QR Code Scanning CTS-QR (by: oretnom23 ) v1.0

![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/oretnom23/CVE-nu11-04/docs/Capture.PNG)

## Vendor:
- [href](https://www.sourcecodester.com/php/14728/covid-19-contact-tracing-system-web-app-qr-code-scanning-using-php-source-code.html)
- 
## Software
- [href](https://www.mediafire.com/file/hnpjyei7saq2h8e/cts_qr_1.zip/file)

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
## Proof:
![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/oretnom23/CVE-nu11-04/docs/CVE-nu11-04.gif)
- [+][video](https://streamable.com/e6pm04)


## Description:
The Covid-19 Contact Tracing System Web App with QR Code Scanning CTS-QR (by: oretnom23 ) v1.0 is vulnerable in the application /cts_qr/classes/Login.php from SQL-Injection-Bypass-Authentication
m0re info: https://portswigger.net/support/using-sql-injection-to-bypass-authentication. 
The parameter (username) from the login form is not protected correctly and there is no security and escaping from malicious payloads. 
When the user will sending a malicious query or malicious payload to the MySQL server he can bypass the login credentials and take control of the administer account.

## Please, report here:
- [+][href](https://www.youtube.com/watch?v=6voxW97vFMM)
### NOTE:
- - - [+] `The owner is not satisfied with the fact that all his projects are using the same broken MySQL query architecture.` =)

## M0re:
- [+] [href](https://streamable.com/luf1bw)

## Conclusion and solution of the problem:
- [+][href](https://www.nu11secur1ty.com/2021/08/php-sec-login.html)

## BR 
- [+] @nu11secur1ty
