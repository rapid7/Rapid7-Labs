---
title: Cisco Firepower Management Center Lightweight Directory Access Protocol Authentication Bypass Vulnerability
author: wvu-r7
score: 3
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2020-09-23T01:15:00'
created: '2020-01-23T03:26:54.867551'
revision_date: '2020-04-15T18:13:29.068608'
assessment_id: eba61759-ba0e-4c29-8c23-8f41b273ed8f
topic_id: 85a68a9c-871e-4e2c-a97d-15a2f1ff6a11
topic_short_id: g2chhBh0JP
topic_slug: cisco-firepower-management-center-lightweight-directory-access-protocol-authentication-bypass-vulnerability
akb_topic_url: https://attackerkb.com/topics/g2chhBh0JP/cisco-firepower-management-center-lightweight-directory-access-protocol-authentication-bypass-vulnerability
akb_assessment_url: https://attackerkb.com/topics/g2chhBh0JP/cisco-firepower-management-center-lightweight-directory-access-protocol-authentication-bypass-vulnerability#eba61759-ba0e-4c29-8c23-8f41b273ed8f
---

# Cisco Firepower Management Center Lightweight Directory Access Protocol Authentication Bypass Vulnerability

*Assessment by wvu-r7, archived from [AttackerKB](https://attackerkb.com/topics/g2chhBh0JP/cisco-firepower-management-center-lightweight-directory-access-protocol-authentication-bypass-vulnerability#eba61759-ba0e-4c29-8c23-8f41b273ed8f).*

---

We had post-auth RCE in Cisco Firepower Management Console submitted as a module in PR [#7803](https://github.com/rapid7/metasploit-framework/pull/7803). This new vuln nets you admin access to the device ONLY if LDAP authentication is enabled. I don't know how common that configuration is.

While the potential for a shell is nice, admin access to a management center for network security solutions is likely more useful. I also don't know if the admin interface is typically exposed on the WAN side, but I've seen worse. I'd expect to see this exposed on a corporate LAN, though. And if you can turn external access into internal access, it makes little difference.

I don't think there's any cause for panic with this, like Citrix last week, but I'd keep my eye on this one. Cisco hasn't seen any PoCs, but it's only a matter of time.
