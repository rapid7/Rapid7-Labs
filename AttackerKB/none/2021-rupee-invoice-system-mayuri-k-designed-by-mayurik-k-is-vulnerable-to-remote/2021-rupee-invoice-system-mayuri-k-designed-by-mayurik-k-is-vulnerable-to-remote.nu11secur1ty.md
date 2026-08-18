---
title: '© 2021 Rupee Invoice System - Mayuri K | Designed by : Mayurik K is vulnerable to remote SQL-Injection-Bypass-Authentication'
author: nu11secur1ty
score: 2
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-09-21T11:43:22.813289'
revision_date: '2021-09-27T14:59:15.461908'
assessment_id: 425a3176-25e2-4d4f-9784-b16fb12ba930
topic_id: 91720611-9f38-4ebc-b15b-e77e7b240304
topic_short_id: IHUP51Y5Gh
topic_slug: 2021-rupee-invoice-system---mayuri-k-designed-by-mayurik-k-is-vulnerable-to-remote-sql-injection-bypass-authentication
akb_topic_url: https://attackerkb.com/topics/IHUP51Y5Gh/2021-rupee-invoice-system---mayuri-k-designed-by-mayurik-k-is-vulnerable-to-remote-sql-injection-bypass-authentication
akb_assessment_url: https://attackerkb.com/topics/IHUP51Y5Gh/2021-rupee-invoice-system---mayuri-k-designed-by-mayurik-k-is-vulnerable-to-remote-sql-injection-bypass-authentication#425a3176-25e2-4d4f-9784-b16fb12ba930
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# © 2021 Rupee Invoice System - Mayuri K | Designed by : Mayurik K is vulnerable to remote SQL-Injection-Bypass-Authentication

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/IHUP51Y5Gh/2021-rupee-invoice-system---mayuri-k-designed-by-mayurik-k-is-vulnerable-to-remote-sql-injection-bypass-authentication#425a3176-25e2-4d4f-9784-b16fb12ba930).*

---

## [CVE-nu11-16-092121](https://www.sourcecodester.com/php/14831/billing-system-project-php-source-code-free-download.html)

## The vendor is so beautiful, but this is not enough ;) 

----------------------------------------------------------------------------------------------------------------------------

![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/mayuri_k/docs/billing-system-project-in-php-source-code-free-download.jpg)

### Description:
The © 2021 Rupee Invoice System - Mayuri K | Designed by: Mayurik K is vulnerable to remote SQL-Injection-Bypass-Authentication. 
remote SQL-Injection-Bypass-Authentication: https://portswigger.net/support/using-sql-injection-to-bypass-authentication. 
The parameter (username) from the login form is not protected correctly and there is no security and escaping from malicious payloads. 
When the user will sending a malicious query or malicious payload to the MySQL server for those three accounts, he can bypass the login credentials and take control of the admin account.

## Broken structure on `login.php` app:
```PHP
$errors = array();

if($_POST) {    

  $username = $_POST['username'];
  $password = $_POST['password'];

  if(empty($username) || empty($password)) {
    if($username == "") {
      $errors[] = "Username is required";
    } 

    if($password == "") {
      $errors[] = "Password is required";
    }
  } else {
    $sql = "SELECT * FROM users WHERE username = ('$username')";
    $result = $connect->query($sql);

    if($result->num_rows == 1) {
      $password = md5($password);
      // exists
      $mainSql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
      $mainResult = $connect->query($mainSql);

      if($mainResult->num_rows == 1) {
        $value = $mainResult->fetch_assoc();
        $user_id = $value['user_id'];

        // set session
        $_SESSION['userId'] = $user_id;?>
```
## Simple fixed, but not enough ;)
[href](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/mayuri_k/docs/fixhaha.gif)

## Decision:
[href](https://www.nu11secur1ty.com/2021/08/php-sec-login.html)

## BR
