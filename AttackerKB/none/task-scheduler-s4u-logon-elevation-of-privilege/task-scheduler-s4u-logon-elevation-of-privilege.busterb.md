---
title: Task Scheduler S4U Logon Elevation of Privilege
author: busterb
score: 1
topic_attacker_value: 3
topic_exploitability: 3.5
created: '2019-05-09T17:57:25.605267'
revision_date: '2020-03-15T04:22:22.595044'
assessment_id: 6cd9f581-ee7e-4479-9320-8e73e89a97e9
topic_id: b3c81855-abd0-4a19-b5ca-7ea60a5837c8
topic_short_id: XPrTC1Xkzb
topic_slug: task-scheduler-s4u-logon-elevation-of-privilege
akb_topic_url: https://attackerkb.com/topics/XPrTC1Xkzb/task-scheduler-s4u-logon-elevation-of-privilege
akb_assessment_url: https://attackerkb.com/topics/XPrTC1Xkzb/task-scheduler-s4u-logon-elevation-of-privilege#6cd9f581-ee7e-4479-9320-8e73e89a97e9
author_ratings:
  attacker-value: 2
  confidence-in-ratings: 5
  effort-to-develop-exploit: 3
  exploitability: 2
  urgent-to-patch: 3
---

# Task Scheduler S4U Logon Elevation of Privilege

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/XPrTC1Xkzb/task-scheduler-s4u-logon-elevation-of-privilege#6cd9f581-ee7e-4479-9320-8e73e89a97e9).*

---

## Details

This is possibly another 'getsystem' technique for UAC bypass.
The effort required to exploit this vulnerability is higher because it requires
a particular set of circumstances that are not universal.

From the report:

> My 2c: You're already an admin, it's not letting you do anything you couldn't already do, it's just not giving you a heads up (UAC warning).
