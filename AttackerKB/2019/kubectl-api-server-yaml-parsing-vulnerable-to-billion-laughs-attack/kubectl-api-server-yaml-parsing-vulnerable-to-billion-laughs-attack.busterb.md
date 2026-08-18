---
title: Kubectl/API Server YAML parsing vulnerable to "Billion Laughs" Attack
author: busterb
score: 2
topic_attacker_value: 1
topic_exploitability: 1
topic_disclosure_date: '2019-10-17T16:15:00'
created: '2019-10-10T19:24:07.320178'
revision_date: '2020-02-13T17:12:00.869517'
assessment_id: 513cccc4-2d7b-4b78-b8fe-1e4ef9d0d01c
topic_id: 3c42d63d-858b-4be3-8c0e-3423577b453b
topic_short_id: fJf0WoJeyw
topic_slug: kubectl-api-server-yaml-parsing-vulnerable-to-billion-laughs-attack
akb_topic_url: https://attackerkb.com/topics/fJf0WoJeyw/kubectl-api-server-yaml-parsing-vulnerable-to-billion-laughs-attack
akb_assessment_url: https://attackerkb.com/topics/fJf0WoJeyw/kubectl-api-server-yaml-parsing-vulnerable-to-billion-laughs-attack#513cccc4-2d7b-4b78-b8fe-1e4ef9d0d01c
author_ratings:
  attacker-value: 1
  confidence-in-ratings: 4
  effort-to-develop-exploit: 2
  exploitability: 1
  urgent-to-patch: 1
  used-successfully: 1
---

# Kubectl/API Server YAML parsing vulnerable to "Billion Laughs" Attack

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/fJf0WoJeyw/kubectl-api-server-yaml-parsing-vulnerable-to-billion-laughs-attack#513cccc4-2d7b-4b78-b8fe-1e4ef9d0d01c).*

---

As I understand it, most kubernetes clusters will require auth or a foothold to reach in the first place. Why would you bother with a DoS attack at that point? Much more attacker value to be had in exploiting the cluster in ways that don't bring it down.

Compare authenticated:
https://www.shodan.io/search?query=kubernetes+401

And unauthenticated searches:
https://www.shodan.io/search?query=kubernetes+%21401
