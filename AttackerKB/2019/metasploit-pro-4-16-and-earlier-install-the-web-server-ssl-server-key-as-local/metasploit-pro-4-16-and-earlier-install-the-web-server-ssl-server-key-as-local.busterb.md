---
title: Metasploit Pro 4.16 and earlier install the web server SSL server.key as local-user readable by default
author: busterb
score: 1
topic_attacker_value: 1
topic_exploitability: 1
topic_disclosure_date: '2019-11-06T19:15:00'
created: '2019-11-14T18:11:16.616954'
revision_date: '2020-02-13T17:11:56.68976'
assessment_id: 8c3026b5-7ae9-4e5f-8237-199a88160374
topic_id: 840afa91-fc8e-4cfb-b206-1aa1b1a1efdd
topic_short_id: QeXKYygs7w
topic_slug: metasploit-pro-4-16-and-earlier-install-the-web-server-ssl-server-key-as-local-user-readable-by-default
akb_topic_url: https://attackerkb.com/topics/QeXKYygs7w/metasploit-pro-4-16-and-earlier-install-the-web-server-ssl-server-key-as-local-user-readable-by-default
akb_assessment_url: https://attackerkb.com/topics/QeXKYygs7w/metasploit-pro-4-16-and-earlier-install-the-web-server-ssl-server-key-as-local-user-readable-by-default#8c3026b5-7ae9-4e5f-8237-199a88160374
author_ratings:
  attacker-value: 1
  effort-to-develop-exploit: 1
  exploitability: 1
  mitigation-strength: 5
  urgent-to-patch: 3
  used-successfully: 5
---

# Metasploit Pro 4.16 and earlier install the web server SSL server.key as local-user readable by default

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/QeXKYygs7w/metasploit-pro-4-16-and-earlier-install-the-web-server-ssl-server-key-as-local-user-readable-by-default#8c3026b5-7ae9-4e5f-8237-199a88160374).*

---

This requires authentication via a remote shell in order to be effective. If an adversary is on your Metasploit Pro machine such that they can access the key in the first place, it's already game-over. So, having the web-server certificate key (which is by default a fake cert anyway) is unlikely to be a high risk for a Metasploit Pro user.
