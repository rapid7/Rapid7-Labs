---
title: 'CTX276688: Citrix Application Delivery Controller, Citrix Gateway, and Citrix SD-WAN WANOP appliance Security Update'
author: busterb
score: 2
topic_attacker_value: 5
topic_exploitability: 0
created: '2020-07-10T23:17:32.725062'
revision_date: '2020-07-11T00:13:46.095642'
assessment_id: 50e7e3c5-644c-46ae-b650-1ef45cec22ad
topic_id: 69741dfd-3169-4113-b9d5-f2d752453cca
topic_short_id: 1gtLOTCYAg
topic_slug: ctx276688-citrix-application-delivery-controller-citrix-gateway-and-citrix-sd-wan-wanop-appliance-security-update
akb_topic_url: https://attackerkb.com/topics/1gtLOTCYAg/ctx276688-citrix-application-delivery-controller-citrix-gateway-and-citrix-sd-wan-wanop-appliance-security-update
akb_assessment_url: https://attackerkb.com/topics/1gtLOTCYAg/ctx276688-citrix-application-delivery-controller-citrix-gateway-and-citrix-sd-wan-wanop-appliance-security-update#50e7e3c5-644c-46ae-b650-1ef45cec22ad
author_ratings:
  attacker-value: 5
  tags:
  - exploited_in_the_wild
  - common_enterprise
  - pre_auth
---

# CTX276688: Citrix Application Delivery Controller, Citrix Gateway, and Citrix SD-WAN WANOP appliance Security Update

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/1gtLOTCYAg/ctx276688-citrix-application-delivery-controller-citrix-gateway-and-citrix-sd-wan-wanop-appliance-security-update#50e7e3c5-644c-46ae-b650-1ef45cec22ad).*

---

Taking a quick look at [NCC group research](https://research.nccgroup.com/2020/07/10/rift-citrix-adc-vulnerabilities-cve-2020-8193-cve-2020-8195-and-cve-2020-8196-intelligence/] on this, it looks like combining the CVE-2020-8193 authentication bypass with one of the other vulnerabilities allows one to steal VPN session data from a device.
