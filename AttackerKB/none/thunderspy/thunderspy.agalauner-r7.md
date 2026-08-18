---
title: ThunderSpy
author: agalauner-r7
score: 13
topic_attacker_value: 1
topic_exploitability: 1
created: '2020-05-11T16:37:02.379519'
revision_date: '2020-06-10T14:19:19.988369'
assessment_id: ac0ad161-61af-45df-a65a-383a8639ceb8
topic_id: f05ac4f4-854a-4a3b-8d2f-14902518b15e
topic_short_id: mPaHZgsUvk
topic_slug: thunderspy
akb_topic_url: https://attackerkb.com/topics/mPaHZgsUvk/thunderspy
akb_assessment_url: https://attackerkb.com/topics/mPaHZgsUvk/thunderspy#ac0ad161-61af-45df-a65a-383a8639ceb8
author_ratings:
  attacker-value: 1
  exploitability: 1
  tags:
  - difficult_to_exploit
  - default_configuration
  - high_privilege_access
  - difficult_to_develop
  - difficult_to_patch
---

# ThunderSpy

*Assessment by agalauner-r7, archived from [AttackerKB](https://attackerkb.com/topics/mPaHZgsUvk/thunderspy#ac0ad161-61af-45df-a65a-383a8639ceb8).*

---

The risks of [DMA attacks](https://en.wikipedia.org/wiki/DMA_attack) over PCI-Express are known for quite some time. Every PCIe device can potentially access physical memory inside a machine and exfiltrate private data like encryption keys or passwords. Modifications are also possible. As Thunderbolt has the capability to tunnel PCIe traffic, this is also possible by external Thunderbolt devices. One of the countermeasures implemented in the Thunderbolt controllers against unknown devices behaving evil is to block them entirely by employing a user configurable whitelist.

The presented vulnerabilities affect these security measures and allow to authenticate malicious devices which then can be used to perform subsequent DMA attacks. The Thunderbolt controller responsible for authenticating the devices has its own microcontroller and runs firmware from a small [SPI](https://en.wikipedia.org/wiki/Serial_Peripheral_Interface) [flash chip](https://en.wikipedia.org/wiki/Flash_memory) usually sitting next to it on the circuit board. The whitelist is stored on this SPI flash chip as well.

If the attacker has physical access to a machine, he can disassemble it, locate the flash chip and read or write it using an external device to tamper with the firmware or the whitelist stored on this device.

After managing to authenticate a malicious thunderbolt device, it is possible to access the main physical memory of the machine using DMA transfers over PCIe. This issue is known for some time and there are other countermeasures in place to prevent malicious DMA accesses. To restrict devices on a PCIe bus from accessing whatever memory they want, the system firmware or operating system can configure the IOMMU to restrict what memory regions can be accessed or not. This is the responsibility of the software running on the system which currently only mac OS seems to perform by default. Also as an IOMMU is a piece of hardware, it needs to be supported by the platform.

Possible mitigations against the attacks:
- Don't let anybody disassemble your machine
- Disable the Thunderbolt controller completely in the BIOS - this means disabling the PCIe device, not only setting the security level to passthrough as this setting can be bypassed using the attack
- Only attach trusted devices to your machine
- Consult the documentation of your hardware and operating system how to configure the IOMMU correctly to prevent malicious DMA memory accesses
