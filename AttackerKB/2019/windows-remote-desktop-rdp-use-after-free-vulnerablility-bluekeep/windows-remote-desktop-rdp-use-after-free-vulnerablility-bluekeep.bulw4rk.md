---
title: Windows Remote Desktop (RDP) Use-after-free vulnerablility, "Bluekeep"
author: bulw4rk
score: 3
topic_attacker_value: 4.5
topic_exploitability: 2.2
topic_disclosure_date: '2019-05-16T19:29:00'
created: '2020-03-29T16:46:17.144704'
revision_date: '2020-06-10T02:40:28.694268'
assessment_id: a9be2b4f-415e-469b-b767-33ef3264d546
topic_id: 131226a6-a1e9-48a1-a5d0-ac94baf8dfd2
topic_short_id: huQasjoVMS
topic_slug: windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep
akb_topic_url: https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep
akb_assessment_url: https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep#a9be2b4f-415e-469b-b767-33ef3264d546
author_ratings:
  attacker-value: 5
  exploitability: 3
  tags:
  - common_enterprise
  - high_privilege_access
---

# Windows Remote Desktop (RDP) Use-after-free vulnerablility, "Bluekeep"

*Assessment by bulw4rk, archived from [AttackerKB](https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep#a9be2b4f-415e-469b-b767-33ef3264d546).*

---

**Description**

A vulnerability in the RDP windows service allows the execution of malicious code with the injection of code in the request for a RDP connection. The exploitation of this vulnerability may be used for performing a DoS (Denial Of Service) attack or executing code in a remote system.

For the safe and satisfactory exploitation of this vulnerability, it is recommended to identify the target machine so the exploit is reliably crafted.

**Mitigation**

- Apply the corresponding security patches released by Microsoft (supported and unsupported OSs)
- Disabling RDP service where no needed and controlling its exposure using a FW internally and externally
- Enabling network level authentication in RDP services

**Affected Systems**

The following Operating System are affected if they have not been patched:

- Windows Vista
- Windows 7
- Windows XP
- Windows Server 2003
- Windows Server 2008

**References**

- The exploit is now included in Metasploit. (The exploit may requier some tuning)
- https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708

**Personal Notes**

When I have released this assessment, the coronavirus crisis has required for a massive number of companies and entities to go "remote work", and an important increment in exposed RDP services on the internet has been detected. Need to emphasize ICS environments and the infrastructure supporting heath services.
