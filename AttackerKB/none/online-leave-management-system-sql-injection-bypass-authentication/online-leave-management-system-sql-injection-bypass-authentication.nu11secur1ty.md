---
title: Online Leave Management System SQL-Injection-Bypass-Authentication
author: nu11secur1ty
score: 2
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-08-31T14:25:00.9645'
revision_date: '2021-08-31T16:35:24.089985'
assessment_id: 0a9c6ea7-9cb1-4ae5-9717-5ed2ffdf51d5
topic_id: 529ab97b-7794-4dff-9a4d-491168bdc2f6
topic_short_id: 2ZlFqBSg7r
topic_slug: online-leave-management-system-sql-injection-bypass-authentication
akb_topic_url: https://attackerkb.com/topics/2ZlFqBSg7r/online-leave-management-system-sql-injection-bypass-authentication
akb_assessment_url: https://attackerkb.com/topics/2ZlFqBSg7r/online-leave-management-system-sql-injection-bypass-authentication#0a9c6ea7-9cb1-4ae5-9717-5ed2ffdf51d5
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# Online Leave Management System SQL-Injection-Bypass-Authentication

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/2ZlFqBSg7r/online-leave-management-system-sql-injection-bypass-authentication#0a9c6ea7-9cb1-4ae5-9717-5ed2ffdf51d5).*

---

# CVE-nu11-03
## Online Leave Management System SQL-Injection-Bypass-Authentication:
![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/oretnom23/CVE-nu11-03/Capture.PNG)

## Vendor:
- [+] [href](https://www.youtube.com/channel/UCEHRo563wbV8JrRSdNajTvQ)

## Description:
The OLMS - PHP (by: oretnom23 ) v1.0 is vulnerable in the application /leave_system/classes/Login.php from SQL-Injection-Bypass-Authentication
m0re info: https://portswigger.net/support/using-sql-injection-to-bypass-authentication. 
The parameter (username) from the login form is not protected correctly and there is no security and escaping from malicious payloads. 
When the user will sending a malicious query or malicious payload to the MySQL server he can bypass the login credentials and take control of the administer account.

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
- [+][href](https://streamable.com/0i84gn)

## Conclusion and solution of the problem:
- [+][href](https://www.nu11secur1ty.com/2021/08/php-sec-login.html)

## BR 
- [+] @nu11secur1ty
