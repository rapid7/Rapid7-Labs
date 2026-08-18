---
title: 'POMS-PHP (by: oretnom23 ) v1.0 is vulnerable to remote SQL-Injection-Bypass-Authentication'
author: nu11secur1ty
score: 1
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-09-09T12:04:53.839273'
revision_date: '2021-09-09T14:34:58.673737'
assessment_id: afe8c8ce-f69f-4c41-b6a3-8024e5297308
topic_id: c5409ce1-48b8-4f5a-a3d1-af6008109157
topic_short_id: q6yY2Ylb2E
topic_slug: poms-php-by-oretnom23-v1-0-is-vulnerable-to-remote-sql-injection-bypass-authentication
akb_topic_url: https://attackerkb.com/topics/q6yY2Ylb2E/poms-php-by-oretnom23-v1-0-is-vulnerable-to-remote-sql-injection-bypass-authentication
akb_assessment_url: https://attackerkb.com/topics/q6yY2Ylb2E/poms-php-by-oretnom23-v1-0-is-vulnerable-to-remote-sql-injection-bypass-authentication#afe8c8ce-f69f-4c41-b6a3-8024e5297308
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# POMS-PHP (by: oretnom23 ) v1.0 is vulnerable to remote SQL-Injection-Bypass-Authentication

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/q6yY2Ylb2E/poms-php-by-oretnom23-v1-0-is-vulnerable-to-remote-sql-injection-bypass-authentication#afe8c8ce-f69f-4c41-b6a3-8024e5297308).*

---

## [CVE-nu11-09](https://www.sourcecodester.com/php/14935/purchase-order-management-system-using-php-free-source-code.html#comment-form)
![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/oretnom23/CVE-nu11-09/docs/Capture.PNG)

### Vulnerability Description:
The POMS-PHP (by: oretnom23 ) v1.0 is vulnerable to remote SQL-Injection-Bypass-Authentication for the admin account in app /purchase_order/classes/Login.php. 
remote SQL-Injection-Bypass-Authentication: https://portswigger.net/support/using-sql-injection-to-bypass-authentication. 
The parameter (username) from the login form is not protected correctly and there is no security and escaping from malicious payloads. 
When the user will sending a malicious query or malicious payload to the MySQL server, he can bypass the login credentials and take control of the admin account.

### Vulnerability `PHP` code:

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
			$this->settings->set_userdata('login_type',1);
		return json_encode(array('status'=>'success'));
		}else{
		return json_encode(array('status'=>'incorrect','last_qry'=>"SELECT * from users where username = '$username' and password = md5('$password') "));
		}
	}
 ```
## Responding from the hacked target:

- - - `PoC + checks` = `PoC-CVE-nu11-09-rfth.py`

```cmd
C:\Users\venvaropt\Desktop\CVE-nu11-09-09092021>python PoC-CVE-nu11-09.py

DevTools listening on ws://127.0.0.1:63704/devtools/browser/bf18be59-2361-4c08-82dc-689957d5bf9e

The payload for CVE-nu11-09 is deployed and your admin account is PWNED by SQL - Injection

Please see the screenshot poc.png to see if your exploit is working =) BR @nu11secur1ty

This target gives a positive <Response [200]> from inside, after bypassing the login :D

C:\Users\venvaropt\Desktop\CVE-nu11-09-09092021>
```
![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/oretnom23/CVE-nu11-09/docs/responding-from-the-hacked-target.PNG)
 
## Exploit technique:
 
[Python](https://www.python.org/) + [Selenium](https://www.selenium.dev/) + hidden login && screenshot

## Proof:
[href](https://streamable.com/47kd87)
 
## BR
 - - - @nu11secur1ty
