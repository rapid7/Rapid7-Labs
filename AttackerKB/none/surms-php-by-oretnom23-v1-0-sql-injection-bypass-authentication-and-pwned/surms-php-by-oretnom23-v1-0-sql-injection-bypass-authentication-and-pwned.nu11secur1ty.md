---
title: 'SURMS - PHP (by: oretnom23 ) v1.0 SQL-Injection-Bypass-Authentication and PWNED PHPSESSID Hijacking'
author: nu11secur1ty
score: 1
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-09-07T10:58:18.827979'
revision_date: '2021-09-07T11:12:53.911747'
assessment_id: c2009202-e813-4500-8d6f-8e9c364db159
topic_id: d3bccee1-ae82-4a8f-b215-08715b42a3ac
topic_short_id: BdNrFV4tQ1
topic_slug: surms---php-by-oretnom23-v1-0-sql-injection-bypass-authentication-and-pwned-phpsessid-hijacking
akb_topic_url: https://attackerkb.com/topics/BdNrFV4tQ1/surms---php-by-oretnom23-v1-0-sql-injection-bypass-authentication-and-pwned-phpsessid-hijacking
akb_assessment_url: https://attackerkb.com/topics/BdNrFV4tQ1/surms---php-by-oretnom23-v1-0-sql-injection-bypass-authentication-and-pwned-phpsessid-hijacking#c2009202-e813-4500-8d6f-8e9c364db159
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# SURMS - PHP (by: oretnom23 ) v1.0 SQL-Injection-Bypass-Authentication and PWNED PHPSESSID Hijacking

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/BdNrFV4tQ1/surms---php-by-oretnom23-v1-0-sql-injection-bypass-authentication-and-pwned-phpsessid-hijacking#c2009202-e813-4500-8d6f-8e9c364db159).*

---

## [CVE-nu11-08-09072021](https://www.sourcecodester.com/php/14932/storage-unit-rental-management-system-using-php-free-source-code.html)
## [VENDOR](https://www.sourcecodester.com/user/257130/activity)
![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/oretnom23/CVE-nu11-08-09072021/Capture.PNG)

### Vulnerability Description:
The SURMS - PHP (by: oretnom23 ) v1.0 is vulnerable from remote SQL-Injection-Bypass-Authentication for the admin account in app: /storage/classes/Login.php and XSS PWNED PHPSESSID Hijacking in app "tenants". 
Remote SQL-Injection-Bypass-Authentication: https://portswigger.net/support/using-sql-injection-to-bypass-authentication. 
The parameter (username) from the login form is not protected correctly and there is no security and escaping from malicious payloads. 
When the user will sending a malicious query or malicious payload to the MySQL server for those three accounts, he can bypass the login credentials and take control of these accounts.
And the second time he can access the admin account by using the PHPSESSID Hijacking technique.

## Vulnerable PHP code:
```PHP
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
## Proof:
[href](https://streamable.com/9efynl)
