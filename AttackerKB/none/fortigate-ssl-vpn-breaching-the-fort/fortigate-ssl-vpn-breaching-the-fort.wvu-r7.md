---
title: FortiGate SSL VPN "Breaching the Fort"
author: wvu-r7
score: 4
topic_attacker_value: 5
topic_exploitability: 1
created: '2020-09-25T22:35:12.241921'
revision_date: '2020-09-30T19:14:31.218179'
assessment_id: 8487a5d9-76c4-4b0e-b342-0c61b42e0e64
topic_id: b95e8026-2c05-4f41-ac50-f16cef790e9d
topic_short_id: 2Z51tgXxMl
topic_slug: fortigate-ssl-vpn-breaching-the-fort
akb_topic_url: https://attackerkb.com/topics/2Z51tgXxMl/fortigate-ssl-vpn-breaching-the-fort
akb_assessment_url: https://attackerkb.com/topics/2Z51tgXxMl/fortigate-ssl-vpn-breaching-the-fort#8487a5d9-76c4-4b0e-b342-0c61b42e0e64
author_ratings:
  attacker-value: 5
  exploitability: 1
---

# FortiGate SSL VPN "Breaching the Fort"

*Assessment by wvu-r7, archived from [AttackerKB](https://attackerkb.com/topics/2Z51tgXxMl/fortigate-ssl-vpn-breaching-the-fort#8487a5d9-76c4-4b0e-b342-0c61b42e0e64).*

---

# Analysis

The VPN client verifies that certificates are signed by a) Fortinet themselves or b) a "trusted" CA. The Fortinet-signed certificate does not have its server name verified, and an attacker can substitute in another Fortinet-signed certificate for use in a [man-in-the-middle (MITM) attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack).

The attacker may then be able to retrieve VPN user credentials and tokens from the captured network traffic.

# Exploitability

The attacker needs a Fortinet-signed certificate as well as presence on the target's network to initiate the MITM attack.  The certificate can be obtained from another Fortinet device, and the network access can be obtained through a compromised IoT device as the researchers suggested.

All in all, exploitability is lower due to the targeted exploit chain.

# Impact

An attacker may obtain VPN access to an organization's network and its services.

# Recommendations

VPN administrators should use only certificates that are signed by a trusted CA.
