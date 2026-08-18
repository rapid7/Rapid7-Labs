---
title: Simple Membership System using PHP and AJAX is vulnerable to remote SQL-Injection-Bypass-Authentication/XSS-Stored PWNED
author: nu11secur1ty
score: 1
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-09-17T08:39:52.287284'
revision_date: '2021-09-17T08:46:22.006406'
assessment_id: f0a90887-598a-4919-80aa-6ddcf4793d13
topic_id: b7e47bcc-b318-40b0-a84a-be6df981f1ff
topic_short_id: 0GGnvLKXyl
topic_slug: simple-membership-system-using-php-and-ajax-is-vulnerable-to-remote-sql-injection-bypass-authentication-xss-stored-pwned
akb_topic_url: https://attackerkb.com/topics/0GGnvLKXyl/simple-membership-system-using-php-and-ajax-is-vulnerable-to-remote-sql-injection-bypass-authentication-xss-stored-pwned
akb_assessment_url: https://attackerkb.com/topics/0GGnvLKXyl/simple-membership-system-using-php-and-ajax-is-vulnerable-to-remote-sql-injection-bypass-authentication-xss-stored-pwned#f0a90887-598a-4919-80aa-6ddcf4793d13
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# Simple Membership System using PHP and AJAX is vulnerable to remote SQL-Injection-Bypass-Authentication/XSS-Stored PWNED

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/0GGnvLKXyl/simple-membership-system-using-php-and-ajax-is-vulnerable-to-remote-sql-injection-bypass-authentication-xss-stored-pwned#f0a90887-598a-4919-80aa-6ddcf4793d13).*

---

## [CVE-nu11-13-091721](https://www.sourcecodester.com/php/11072/simple-membership-system.html)
![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/razormist/docs/screen.png)

## Vulnerability `PHP`app code `validate.php`and structure also 
```php
<?php
	require_once 'conn.php';
	$username = $_POST['username'];
	$password = $_POST['password'];
	$query = $conn->query("SELECT * FROM `admin` WHERE `username` = '$username' && `password` = '$password'") or die(mysqli_error());
	$validate = $query->num_rows;
	$fetch = $query->fetch_array();
	if($validate > 0){
		echo "Success";
		session_start();
		$_SESSION['admin_id'] = $fetch['admin_id'];
	}else{
		echo "Error";
	}
```
## Simple fix.
-  WARNING: THIS IS `NOT FIX` OF THE PROBLEM, Just an example =)

```php
<?php
	require_once 'conn.php';
	$username = $_POST['username'];
	$password = $_POST['password'];
	$query = $conn->query("SELECT * FROM `admin` WHERE `username` = ('$username') && `password` = '$password'") or die(mysqli_error());
	$validate = $query->num_rows;
	$fetch = $query->fetch_array();
	if($validate > 0){
		echo "Success";
		session_start();
		$_SESSION['admin_id'] = $fetch['admin_id'];
	}else{
		echo "Error";
	}
```
### Description:
The Simple Membership System using PHP and AJAX is vulnerable to remote SQL-Injection-Bypass-Authentication for the admin account/XSS-Stored PWNED.
remote SQL-Injection-Bypass-Authentication: https://portswigger.net/support/using-sql-injection-to-bypass-authentication. 
The parameters (username and password) from the login form is not protected correctly and there is no security and escaping from malicious payloads. 
When the user will sending a malicious query or malicious payload to the MySQL server for login to the admin account on the system, 
he can bypass the login credentials and take control of this account. And the second time he can adding an payload by using XSS-Stored 

### BR 
- [+] @nu11secur1ty System Administrator - Infrastructure and Penetration Testing Engineer

-------------------------------------------------------------------
### Reproduce: 
[href](https://github.com/nu11secur1ty/CVE-nu11secur1ty/tree/main/vendors/razormist)

### Proof: 
[href](https://streamable.com/21cj5f)

### BR nu11secur1ty
