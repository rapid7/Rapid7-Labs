---
title: Webmin password_change.cgi Command Injection
author: KoelhoSec
score: 0
topic_attacker_value: 5
topic_exploitability: 4.777777777777778
topic_disclosure_date: '2019-08-16T03:15:00'
created: '2021-04-09T02:48:38.158372'
revision_date: '2021-04-20T15:28:53.444402'
assessment_id: f9c47c50-f559-443f-ba90-053f2008a6bf
topic_id: ea90a258-8e7f-49cd-a730-6d8457a421d7
topic_short_id: hxx3zmiCkR
topic_slug: webmin-password-change-cgi-command-injection
akb_topic_url: https://attackerkb.com/topics/hxx3zmiCkR/webmin-password-change-cgi-command-injection
akb_assessment_url: https://attackerkb.com/topics/hxx3zmiCkR/webmin-password-change-cgi-command-injection#f9c47c50-f559-443f-ba90-053f2008a6bf
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# Webmin password_change.cgi Command Injection

*Assessment by KoelhoSec, archived from [AttackerKB](https://attackerkb.com/topics/hxx3zmiCkR/webmin-password-change-cgi-command-injection#f9c47c50-f559-443f-ba90-053f2008a6bf).*

---

MetaSploit module available:
exploit/linux/http/webmin_backdoor

Description:
  This module exploits a backdoor in Webmin versions 1.890 through 
  1.920. Only the SourceForge downloads were backdoored, but they are 
  listed as official downloads on the project's site. Unknown 
  attacker(s) inserted Perl qx statements into the build server's 
  source code on two separate occasions: once in April 2018, 
  introducing the backdoor in the 1.890 release, and in July 2018, 
  reintroducing the backdoor in releases 1.900 through 1.920. Only 
  version 1.890 is exploitable in the default install. Later affected 
  versions require the expired password changing feature to be 
  enabled.
