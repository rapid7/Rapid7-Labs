---
title: 'Junos Space: Malicious HTTP packets sent to Junos Space allow an attacker to view all files on the device.'
author: rootOptional
score: 3
topic_attacker_value: 5
topic_exploitability: 5
topic_disclosure_date: '2020-01-15T09:15:00'
created: '2020-03-09T19:43:34.105796'
revision_date: '2020-04-28T16:26:41.311385'
assessment_id: 5985399a-0f85-4c68-a182-f8ff8e89453e
topic_id: 23437d69-a42d-46bb-b507-61ee0448251f
topic_short_id: cRy9l2YZ4Y
topic_slug: junos-space-malicious-http-packets-sent-to-junos-space-allow-an-attacker-to-view-all-files-on-the-device
akb_topic_url: https://attackerkb.com/topics/cRy9l2YZ4Y/junos-space-malicious-http-packets-sent-to-junos-space-allow-an-attacker-to-view-all-files-on-the-device
akb_assessment_url: https://attackerkb.com/topics/cRy9l2YZ4Y/junos-space-malicious-http-packets-sent-to-junos-space-allow-an-attacker-to-view-all-files-on-the-device#5985399a-0f85-4c68-a182-f8ff8e89453e
author_ratings:
  attacker-value: 5
  exploitability: 5
  tags:
  - easy_to_develop
  - pre_auth
---

# Junos Space: Malicious HTTP packets sent to Junos Space allow an attacker to view all files on the device.

*Assessment by rootOptional, archived from [AttackerKB](https://attackerkb.com/topics/cRy9l2YZ4Y/junos-space-malicious-http-packets-sent-to-junos-space-allow-an-attacker-to-view-all-files-on-the-device#5985399a-0f85-4c68-a182-f8ff8e89453e).*

---

The vulnerability allows a malicious actor access to any files within the system via a local file inclusion. This isn't a vulnerability that requires a heap of knowledge, just enough to craft the http request. It's also vulnerable in a series of versions prior to the release of 19.4R1. Though these systems aren't commonly found.
