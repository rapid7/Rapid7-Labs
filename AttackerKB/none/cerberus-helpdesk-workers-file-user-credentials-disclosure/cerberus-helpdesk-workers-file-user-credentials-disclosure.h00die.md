---
title: Cerberus Helpdesk Workers File User Credentials Disclosure
author: h00die
score: 1
topic_attacker_value: 3
topic_exploitability: 5
created: '2020-03-25T00:30:18.103445'
revision_date: '2020-03-25T00:30:18.106309'
assessment_id: b9c64198-cc82-4edd-ae38-00b85c3d2ef2
topic_id: 5ed4dbaa-c7bf-4e78-b8d0-0d65cd2bc083
topic_short_id: J7luhKCp6r
topic_slug: cerberus-helpdesk-workers-file-user-credentials-disclosure
akb_topic_url: https://attackerkb.com/topics/J7luhKCp6r/cerberus-helpdesk-workers-file-user-credentials-disclosure
akb_assessment_url: https://attackerkb.com/topics/J7luhKCp6r/cerberus-helpdesk-workers-file-user-credentials-disclosure#b9c64198-cc82-4edd-ae38-00b85c3d2ef2
author_ratings:
  attacker-value: 3
  exploitability: 5
  tags:
  - default_configuration
  - easy_to_develop
  - pre_auth
---

# Cerberus Helpdesk Workers File User Credentials Disclosure

*Assessment by h00die, archived from [AttackerKB](https://attackerkb.com/topics/J7luhKCp6r/cerberus-helpdesk-workers-file-user-credentials-disclosure#b9c64198-cc82-4edd-ae38-00b85c3d2ef2).*

---

Found this software in an enterprise environment.  The `/storage/tmp/devblocks_cache---ch_workers`and `/storage/tmp/zend_cache---ch_workers`files contain lots of data, however the only things of value are a list of usernames and password hashes.  When found in an enterprise, this gave us over 200 MD5 hashes, which was a huge win.  Never seen the software before or after though.
