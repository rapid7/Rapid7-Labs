---
title: Ripple20 Treck TCP/IP Stack Vulnerabilities
author: busterb
score: 7
topic_attacker_value: 2
topic_exploitability: 1
created: '2020-06-17T18:03:08.215327'
revision_date: '2020-06-17T21:43:51.630677'
assessment_id: 40b7414d-5746-42c8-8d57-a5e88b54591f
topic_id: 4e502c55-e1b7-445e-b426-649c863c1b93
topic_short_id: EZhbaWNnwV
topic_slug: ripple20-treck-tcp-ip-stack-vulnerabilities
akb_topic_url: https://attackerkb.com/topics/EZhbaWNnwV/ripple20-treck-tcp-ip-stack-vulnerabilities
akb_assessment_url: https://attackerkb.com/topics/EZhbaWNnwV/ripple20-treck-tcp-ip-stack-vulnerabilities#40b7414d-5746-42c8-8d57-a5e88b54591f
author_ratings:
  attacker-value: 2
  exploitability: 1
  tags:
  - common_enterprise
  - default_configuration
  - difficult_to_exploit
  - difficult_to_develop
---

# Ripple20 Treck TCP/IP Stack Vulnerabilities

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/EZhbaWNnwV/ripple20-treck-tcp-ip-stack-vulnerabilities#40b7414d-5746-42c8-8d57-a5e88b54591f).*

---

This may be interesting to exploit when one has a particular device in mind, and it provides some sort of useful access or control, but there is not going to be an apocalypse of Ripple20 exploits for a few reasons:
 
 - Every target device has to have a tailor-made exploit written for it, outside of a DoS.
 - There is no low-hanging fruit here for actual code execution. Those hundreds of vendors are going to have hundreds of ways they integrated this thing, though you may find some commonalities when folks use the same board support package (BSP) for reference designs.
 - Getting malformed packets into a target device _remotely_ is a lot harder than you'd think these days. Often times, this might as well be considered a local attack, since a lot of edge and intermediate devices will discard many of the malformed packets involved here. That's why I'm tagging 'Requires physical access', because it's practically the case.

There's a reason why devices like this have been off-limits for vuln scans and penetration tests for years. It's because the vendors and users knew their stacks were fragile. This is just reality the infosec world is finally catching up. This isn't the first exploration of an embedded stack with problems, and it will most definitely not be the last. Whether this makes a change in the industry is a bigger question.
