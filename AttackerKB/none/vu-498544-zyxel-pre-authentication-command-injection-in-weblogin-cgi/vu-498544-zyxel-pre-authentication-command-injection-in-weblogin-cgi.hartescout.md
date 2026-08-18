---
title: 'VU#498544 ZyXEL pre-authentication command injection in weblogin.cgi '
author: hartescout
score: 3
topic_attacker_value: 4
topic_exploitability: 2
created: '2020-02-26T23:18:54.731382'
revision_date: '2020-08-28T18:03:55.41588'
assessment_id: e6de1802-320e-4959-a789-68d031ff4a59
topic_id: 6b3d1206-72db-4bea-a98f-4117e0936c39
topic_short_id: er2aKJLbEI
topic_slug: vu-498544-zyxel-pre-authentication-command-injection-in-weblogin-cgi
akb_topic_url: https://attackerkb.com/topics/er2aKJLbEI/vu-498544-zyxel-pre-authentication-command-injection-in-weblogin-cgi
akb_assessment_url: https://attackerkb.com/topics/er2aKJLbEI/vu-498544-zyxel-pre-authentication-command-injection-in-weblogin-cgi#e6de1802-320e-4959-a789-68d031ff4a59
author_ratings:
  attacker-value: 4
  exploitability: 2
  tags:
  - high_privilege_access
  - easy_to_develop
  - common_enterprise
---

# VU#498544 ZyXEL pre-authentication command injection in weblogin.cgi 

*Assessment by hartescout, archived from [AttackerKB](https://attackerkb.com/topics/er2aKJLbEI/vu-498544-zyxel-pre-authentication-command-injection-in-weblogin-cgi#e6de1802-320e-4959-a789-68d031ff4a59).*

---

" Multiple ZyXEL devices achieve authentication by using the weblogin.cgi CGI executable. This program fails to properly sanitize the username parameter that is passed to it. If the username parameter contains certain characters, it can allow command injection with the privileges of the web server that runs on the ZyXEL device. Although the web server does not run as the root user, many ZyXEL devices include a setuid utility that can be leveraged to run any command with root privileges. As such, it should be assumed that exploitation of this vulnerability can lead to remote code execution with root privileges.

Exploit code for this vulnerability that targets NAS devices is available on the internet. "

Exploits are available. What interests me is this shodan.io search posted with 138,000+ devices still vulnerable. A firmware update has been released for most versions of device however, " Block access to the ZyXEL device web interface " is the advice for remaining or an alternative. 
Here is the shodan search I put in as a reference for the topic as well. Again, you're expert opinion is much more valuable than mine at this early stage. I am unfortunately unable to test these in my lab environment due to other commitments. 

edit: I might be mistaken CVE-2020-9054 is listed as the exploit here: https://kb.cert.org/artifacts/cve-2020-9054.html

https://beta.shodan.io/search?query=ssl.cert.subject.CN%3Ausg
https://www.nist.gov/fusion-search?s=CVE-2020-9054
https://twitter.com/wdormann/status/1231987991473602561
