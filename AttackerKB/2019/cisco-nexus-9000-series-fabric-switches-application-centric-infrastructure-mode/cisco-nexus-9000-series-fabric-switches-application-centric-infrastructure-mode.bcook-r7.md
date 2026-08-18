---
title: Cisco Nexus 9000 Series Fabric Switches Application Centric Infrastructure Mode Default SSH Key Vulnerability
author: bcook-r7
score: 2
topic_attacker_value: 5
topic_exploitability: 1
topic_disclosure_date: '2019-05-03T17:29:00'
created: '2019-05-09T17:57:20.373136'
revision_date: '2020-03-15T04:22:22.595044'
assessment_id: a6930147-c83a-4a06-867b-2e4bff5793b9
topic_id: a29f033f-47f8-4658-b470-4a3f541e9175
topic_short_id: KmiVPM0LeJ
topic_slug: cisco-nexus-9000-series-fabric-switches-application-centric-infrastructure-mode-default-ssh-key-vulnerability
akb_topic_url: https://attackerkb.com/topics/KmiVPM0LeJ/cisco-nexus-9000-series-fabric-switches-application-centric-infrastructure-mode-default-ssh-key-vulnerability
akb_assessment_url: https://attackerkb.com/topics/KmiVPM0LeJ/cisco-nexus-9000-series-fabric-switches-application-centric-infrastructure-mode-default-ssh-key-vulnerability#a6930147-c83a-4a06-867b-2e4bff5793b9
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 5
  effort-to-develop-exploit: 3
  exploitability: 1
  urgent-to-patch: 4
---

# Cisco Nexus 9000 Series Fabric Switches Application Centric Infrastructure Mode Default SSH Key Vulnerability

*Assessment by bcook-r7, archived from [AttackerKB](https://attackerkb.com/topics/KmiVPM0LeJ/cisco-nexus-9000-series-fabric-switches-application-centric-infrastructure-mode-default-ssh-key-vulnerability#a6930147-c83a-4a06-867b-2e4bff5793b9).*

---

This requires IPv6 and particular settings to be enabled

Waiting for machine to boot. This may take a few minutes...
    default: SSH address: 127.0.0.1:2222
    default: SSH username: vagrant
    default: SSH auth method: private key
```

It seems you have to configure the virtual switch with a virtual serial port.

## VM Contents:

There are only a few EXT3 filesystems that have useful data in the VMDK image. I think the most interesting bits are going to be inside of nxos.9.2.2.bin which is perhaps decoded or interpreted by the kernel or bootloader.  The boot screen in the VM looks like it uses a modified version of GRUB and the Linux kernel, though my current environment has insufficient memory to make it actually boot.

```
><fs> add-ro ## Vulnerable targets:

It's not clear if the 9000v virtual switch is vulnerable but that is the easiest to target for now, since it does not need special hardware.

The setup is here: https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/7-x/nx-osv/configuration/guide/b_Cisco_Nexus_9000v/b_Cisco_Nexus_9000v_chapter_011.html

## NXOSV VM download

Downloading the 'Vagrant' image and running it with a basic Vagrantfile showed this output, which hung forever:

```
Bringing machine 'default' up with 'virtualbox' provider...
==> default: Clearing any previously set forwarded ports...
==> default: Clearing any previously set network interfaces...
==> default: Preparing network interfaces based on configuration...
    default: Adapter 1: nat
==> default: Forwarding ports...
    default: 22 (guest) => 2222 (host) (adapter 1)
==> default: Booting VM...
==> default: box-disk1.vmdk
><fs> run
><fs> list-filesystems
/dev/sda1: vfat
/dev/sda2: ext3
/dev/sda3: ext3
/dev/sda4: ext3
/dev/sda5: ext3
/dev/sda6: e
boot
cfglabel.sysmgr
debug
dme
licenses
linux
log
lost+foundxt3
/dev/sda7: ext3
><fs> mount /dev/sda3 /
><fs> ls /
lost+found
><fs> mount /dev/sda1 /
><fs> ls /
EFI
><fs> mount /dev/sda2 /
><fs> ls /
lost+found
><fs> mount /dev/sda3 /
><fs> ls /
lost+found
><fs> mount /dev/sda4 /
><fs> ls /
nxos.9.2.2.bin
><fs> mount /dev/sda5 /
><fs> ls /
lost+found
><fs> mount /dev/sda6 /
><fs> ls /
ascii
bin
no-erase
><fs> mount /dev/sda7 /
><fs> ls /
lost+found
```

I copied out the .bin file, which appears to be another filesystem.

```
><fs> mount /dev/sda4 /
><fs> copy-out /nxos.9.2.2.bin .

$ file nxos.9.2.2.bin
nxos.9.2.2.bin: DOS/MBR boot sector
```

```
binwalk ./nxos.9.2.2.bin
--------------------------------------------------------------------------------
0             0x0             Netboot image, mode 2
1024          0x400           Microsoft executable, portable (PE)
17844         0x45B4          gzip compressed data, maximum compression, from Unix, last modified: 1970-01-01 00:00:00 (null date)
2010881       0x1EAF01        MySQL ISAM index file Version 7
6283776       0x5FE200        gzip compressed data, maximum compression, from Unix, last modified: 2018-11-05 06:20:17
```
