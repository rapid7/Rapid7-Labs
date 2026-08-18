---
title: 'eLearning V2(by: oretnom23) is vulnerable from remote SQL-Injection-Bypass-Authentication'
author: nu11secur1ty
score: 1
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-09-06T10:08:01.352975'
revision_date: '2021-09-07T08:39:57.492237'
assessment_id: 3a825cee-23b3-451c-a3c3-e3738e082ba4
topic_id: 17195884-3f5f-4379-953d-48b53037deef
topic_short_id: AJ1zQu7fms
topic_slug: elearning-v2-by-oretnom23-is-vulnerable-from-remote-sql-injection-bypass-authentication
akb_topic_url: https://attackerkb.com/topics/AJ1zQu7fms/elearning-v2-by-oretnom23-is-vulnerable-from-remote-sql-injection-bypass-authentication
akb_assessment_url: https://attackerkb.com/topics/AJ1zQu7fms/elearning-v2-by-oretnom23-is-vulnerable-from-remote-sql-injection-bypass-authentication#3a825cee-23b3-451c-a3c3-e3738e082ba4
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# eLearning V2(by: oretnom23) is vulnerable from remote SQL-Injection-Bypass-Authentication

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/AJ1zQu7fms/elearning-v2-by-oretnom23-is-vulnerable-from-remote-sql-injection-bypass-authentication#3a825cee-23b3-451c-a3c3-e3738e082ba4).*

---

## [CVE-nu11-07](https://www.sourcecodester.com/php/14929/online-learning-system-v2-using-php-free-source-code.html)
## [VENDOR](https://www.sourcecodester.com/user/257130/activity)

- - - ## eLearning V2(by: oretnom23) is vulnerable from remote SQL-Injection-Bypass-Authentication
 
![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/oretnom23/CVE-nu11-07/docs/lesson.png)

### Description:
The eLearning V2(by: oretnom23) is vulnerable from remote SQL-Injection-Bypass-Authentication in 3 accounts of the system (admin, Faculty & Student) in app /elearning/classes/Login.php.
remote SQL-Injection-Bypass-Authentication: https://portswigger.net/support/using-sql-injection-to-bypass-authentication. 
The parameter (username, faculty_id, and student_id) from the login form is not protected correctly and there is no security and escaping from malicious payloads. 
When the user will sending a malicious query or malicious payload to the MySQL server for those three accounts, he can bypass the login credentials and take control of these accounts.


- - - Vulnerable `PHP` app code in `/elearning/classes/Login.php`

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
		$sy = $this->conn->query("SELECT * FROM academic_year where status = 1");
		foreach($sy->fetch_array() as $k =>$v){
			if(!is_numeric($k)){
			$this->settings->set_userdata('academic_'.$k,$v);
			}
		}
		return json_encode(array('status'=>'success'));
		}else{
		return json_encode(array('status'=>'incorrect','last_qry'=>"SELECT * from users where username = '$username' and password = md5('$password') "));
		}
	}
	public function flogin(){
		extract($_POST);

		$qry = $this->conn->query("SELECT * from faculty where  faculty_id = '$faculty_id' and `password` = '".md5($password)."' ");
		if($qry->num_rows > 0){
			foreach($qry->fetch_array() as $k => $v){
				if(!is_numeric($k)){
					$this->settings->set_userdata($k,$v);
				}

			}
			$this->settings->set_userdata('login_type',2);
			$sy = $this->conn->query("SELECT * FROM academic_year where status = 1");
		foreach($sy->fetch_array() as $k =>$v){
			if(!is_numeric($k)){
			$this->settings->set_userdata('academic_'.$k,$v);
			}
		}
			return json_encode(array('status'=>'success'));
		}else{
		return json_encode(array('status'=>'incorrect'));
		}
	}
	public function slogin(){
		extract($_POST);

		$qry = $this->conn->query("SELECT * from students where  student_id = '$student_id' and `password` = '".md5($password)."' ");
		if($qry->num_rows > 0){
			foreach($qry->fetch_array() as $k => $v){
				if(!is_numeric($k)){
					$this->settings->set_userdata($k,$v);
				}

			}
```

-------------------------------------------------------------------
### CONCLUSION: 

- This vendor must STOP creating all these broken projects and vulnerable software programs, probably he is not a developer!

- [+] by @nu11secur1ty System Administrator - Infrastructure and Penetration Testing Engineer

-------------------------------------------------------------------

## Reproduce:
```url
https://github.com/nu11secur1ty/CVE-nu11secur1ty/tree/main/vendors/oretnom23/CVE-nu11-07
```

## Proof: 
[href](https://streamable.com/j44hz0)

## BR
@nu11secur1ty
