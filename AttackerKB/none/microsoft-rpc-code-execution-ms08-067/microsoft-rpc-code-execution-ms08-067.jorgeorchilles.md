---
title: Microsoft RPC Code Execution MS08-067
author: jorgeorchilles
score: 2
topic_attacker_value: 5
topic_exploitability: 5
created: '2020-04-11T16:59:55.761802'
revision_date: '2020-04-13T07:38:16.12172'
assessment_id: bb222ed6-8a86-4918-9011-bc69801f4fe8
topic_id: 445f1cac-c379-466a-ab3a-36c33d2aa1f5
topic_short_id: 8vxf8xuT2N
topic_slug: microsoft-rpc-code-execution-ms08-067
akb_topic_url: https://attackerkb.com/topics/8vxf8xuT2N/microsoft-rpc-code-execution-ms08-067
akb_assessment_url: https://attackerkb.com/topics/8vxf8xuT2N/microsoft-rpc-code-execution-ms08-067#bb222ed6-8a86-4918-9011-bc69801f4fe8
author_ratings:
  attacker-value: 5
  exploitability: 5
  tags:
  - pre_auth
  - high_privilege_access
  - default_configuration
  - common_enterprise
  - easy_to_develop
---

# Microsoft RPC Code Execution MS08-067

*Assessment by jorgeorchilles, archived from [AttackerKB](https://attackerkb.com/topics/8vxf8xuT2N/microsoft-rpc-code-execution-ms08-067#bb222ed6-8a86-4918-9011-bc69801f4fe8).*

---

MS08-067 was possibly the most popular vulnerability of the 2000s. It allows remote code execution, pre-authentication, against all default Windows operating system configurations of the time. While SMB, should never be exposed on the Internet, once on the internal network, almost all windows systems have it enabled.

Exploitation is trivial (point and shoot) through metasploit: https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi

This exploit was widely used and most notably known for the Conficker worm: https://en.wikipedia.org/wiki/Conficker
