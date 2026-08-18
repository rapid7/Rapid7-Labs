---
title: MailCleaner Authenticated Command Injection
author: jrobles-r7
score: 1
topic_attacker_value: 3
topic_exploitability: 2
topic_disclosure_date: '2019-03-21T16:00:00'
created: '2019-05-09T17:57:34.998654'
revision_date: '2020-03-15T04:22:22.595044'
assessment_id: 1cf2c127-4d07-4faa-b8c5-cc6621d0d0cd
topic_id: 1ebf23ff-8de1-4c84-82c4-07b828119e86
topic_short_id: zl7Y1bgeK8
topic_slug: mailcleaner-authenticated-command-injection
akb_topic_url: https://attackerkb.com/topics/zl7Y1bgeK8/mailcleaner-authenticated-command-injection
akb_assessment_url: https://attackerkb.com/topics/zl7Y1bgeK8/mailcleaner-authenticated-command-injection#1cf2c127-4d07-4faa-b8c5-cc6621d0d0cd
author_ratings:
  attacker-value: 3
  confidence-in-ratings: 3
  exploitability: 2
  offensive-application: not sure
  urgent-to-patch: 4
---

# MailCleaner Authenticated Command Injection

*Assessment by jrobles-r7, archived from [AttackerKB](https://attackerkb.com/topics/zl7Y1bgeK8/mailcleaner-authenticated-command-injection#1cf2c127-4d07-4faa-b8c5-cc6621d0d0cd).*

---

## Details

The /admin/managetracing/search/search endpoint in MailCleaner Community Edition allows an authenticated user to inject operating system commands.
