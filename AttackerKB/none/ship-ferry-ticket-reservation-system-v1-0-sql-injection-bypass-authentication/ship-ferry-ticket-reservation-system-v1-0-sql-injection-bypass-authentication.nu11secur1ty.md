---
title: Ship Ferry Ticket Reservation System v1.0 SQL-Injection-Bypass-Authentication
author: nu11secur1ty
score: 2
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-08-31T14:31:36.998405'
revision_date: '2021-08-31T16:35:07.980424'
assessment_id: 1c0d8076-a017-4ec4-8c9f-61cae15fe6d5
topic_id: 557daa1a-1559-4d19-b391-34833593bb7c
topic_short_id: 4qvzxmn60B
topic_slug: ship-ferry-ticket-reservation-system-v1-0-sql-injection-bypass-authentication
akb_topic_url: https://attackerkb.com/topics/4qvzxmn60B/ship-ferry-ticket-reservation-system-v1-0-sql-injection-bypass-authentication
akb_assessment_url: https://attackerkb.com/topics/4qvzxmn60B/ship-ferry-ticket-reservation-system-v1-0-sql-injection-bypass-authentication#1c0d8076-a017-4ec4-8c9f-61cae15fe6d5
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# Ship Ferry Ticket Reservation System v1.0 SQL-Injection-Bypass-Authentication

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/4qvzxmn60B/ship-ferry-ticket-reservation-system-v1-0-sql-injection-bypass-authentication#1c0d8076-a017-4ec4-8c9f-61cae15fe6d5).*

---

## Ship Ferry Ticket Reservation System `v1.0` 

![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/CVE-nu11-02/docs/Capture.PNG)

### [Vendor](https://www.sourcecodester.com/php/14923/shipferry-ticket-reservation-system-using-php-free-source-code.html)

### Description:
The Ship/Ferry Ticket Reservation System `v1.0` is vulnerable in the application /ship_ticketing/classes/Login.php from [SQL-Injection-Bypass-Authentication](https://portswigger.net/support/using-sql-injection-to-bypass-authentication). 
The parameter (username) from the login form is not protected correctly and there is no security and escaping from malicious payloads. 
When the user will sending a malicious query or malicious payload to the MySQL server he can bypass the login credentials and take control of the administer account.


## Broken structure:
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
---------------------------------------------------------------------------------------------------------------------

## Simple fix, but not enough `strong`!!!:
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
[href](https://streamable.com/h65olk)


### BR
[+] @nu11secur1ty
