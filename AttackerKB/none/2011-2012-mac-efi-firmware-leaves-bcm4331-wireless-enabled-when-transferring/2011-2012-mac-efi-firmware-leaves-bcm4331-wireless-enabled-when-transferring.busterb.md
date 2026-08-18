---
title: 2011/2012 Mac EFI firmware leaves BCM4331 wireless enabled when transferring control to the bootloader/OS
author: busterb
score: 0
topic_attacker_value: 2
topic_exploitability: 1
created: '2019-05-10T20:53:57.017244'
revision_date: '2020-02-13T17:12:38.934725'
assessment_id: f23b546e-0fe0-4784-9d06-c746cb777321
topic_id: 791de258-978f-4690-a175-dc81f56f77f6
topic_short_id: qsVN1r3dnT
topic_slug: 2011-2012-mac-efi-firmware-leaves-bcm4331-wireless-enabled-when-transferring-control-to-the-bootloader-os
akb_topic_url: https://attackerkb.com/topics/qsVN1r3dnT/2011-2012-mac-efi-firmware-leaves-bcm4331-wireless-enabled-when-transferring-control-to-the-bootloader-os
akb_assessment_url: https://attackerkb.com/topics/qsVN1r3dnT/2011-2012-mac-efi-firmware-leaves-bcm4331-wireless-enabled-when-transferring-control-to-the-bootloader-os#f23b546e-0fe0-4784-9d06-c746cb777321
author_ratings:
  attacker-value: 2
  confidence-in-ratings: 5
  effort-to-develop-exploit: 5
  exploitability: 1
  urgent-to-patch: 3
---

# 2011/2012 Mac EFI firmware leaves BCM4331 wireless enabled when transferring control to the bootloader/OS

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/qsVN1r3dnT/2011-2012-mac-efi-firmware-leaves-bcm4331-wireless-enabled-when-transferring-control-to-the-bootloader-os#f23b546e-0fe0-4784-9d06-c746cb777321).*

---

This wasn't vulnerable in OpenBSD, because it didn't free the memory the chip was writing memory to back to the kernel. On Linux boxes running a kernel < 2016, this could be RCE over wireless, and was proven to be a DoS, but for only a short time since the Grub mitigation that put the chip to sleep helped a lot.

Basically depends on a lot of circumstances, on hardware that is increasingly aging and irrelevant.
