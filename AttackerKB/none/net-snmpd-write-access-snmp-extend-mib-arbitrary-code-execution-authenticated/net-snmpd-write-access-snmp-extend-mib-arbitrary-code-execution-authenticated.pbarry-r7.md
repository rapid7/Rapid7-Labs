---
title: Net-SNMPd Write Access SNMP-EXTEND-MIB arbitrary code execution (authenticated)
author: pbarry-r7
score: 1
topic_attacker_value: 4
topic_exploitability: 5
created: '2019-11-20T15:33:18.968066'
revision_date: '2020-02-13T17:11:54.668885'
assessment_id: 5eb932da-dab5-4be1-a832-34b2fdc2705a
topic_id: d9546e0e-61ed-41fe-a988-560b9724729e
topic_short_id: DD2T1c7vQV
topic_slug: net-snmpd-write-access-snmp-extend-mib-arbitrary-code-execution-authenticated
akb_topic_url: https://attackerkb.com/topics/DD2T1c7vQV/net-snmpd-write-access-snmp-extend-mib-arbitrary-code-execution-authenticated
akb_assessment_url: https://attackerkb.com/topics/DD2T1c7vQV/net-snmpd-write-access-snmp-extend-mib-arbitrary-code-execution-authenticated#5eb932da-dab5-4be1-a832-34b2fdc2705a
author_ratings:
  attacker-value: 4
  confidence-in-ratings: 4
  effort-to-develop-exploit: 2
  exploitability: 5
  mitigation-strength: 4
  reliability: 5
  stability: 5
  urgent-to-patch: 3
  used-successfully: 1
---

# Net-SNMPd Write Access SNMP-EXTEND-MIB arbitrary code execution (authenticated)

*Assessment by pbarry-r7, archived from [AttackerKB](https://attackerkb.com/topics/DD2T1c7vQV/net-snmpd-write-access-snmp-extend-mib-arbitrary-code-execution-authenticated#5eb932da-dab5-4be1-a832-34b2fdc2705a).*

---

Unclear if this has been officially patched yet in Net-SNMPd (there are reports that the most-current version is still vulnerable).

One way to remediate would be to set access to READ ONLY instead of READ/WRITE.
