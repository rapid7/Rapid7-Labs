---
title: HP Data Protector Express 6.0.00.11974 dpwintdb.exe Buffer Overflow
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2012-03-14T03:28:00'
created: '2019-09-12T18:07:46.79222'
revision_date: '2020-02-13T17:12:10.466461'
assessment_id: 2c8e2912-5130-49dc-959b-936ac5477a9a
topic_id: 00e78136-70dd-4d9b-bffb-f47a512f8edf
topic_short_id: D6BWATPStq
topic_slug: hp-data-protector-express-6-0-00-11974-dpwintdb-exe-buffer-overflow
akb_topic_url: https://attackerkb.com/topics/D6BWATPStq/hp-data-protector-express-6-0-00-11974-dpwintdb-exe-buffer-overflow
akb_assessment_url: https://attackerkb.com/topics/D6BWATPStq/hp-data-protector-express-6-0-00-11974-dpwintdb-exe-buffer-overflow#2c8e2912-5130-49dc-959b-936ac5477a9a
---

# HP Data Protector Express 6.0.00.11974 dpwintdb.exe Buffer Overflow

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/D6BWATPStq/hp-data-protector-express-6-0-00-11974-dpwintdb-exe-buffer-overflow#2c8e2912-5130-49dc-959b-936ac5477a9a).*

---

At this moment metasploit has available a module for CVE-2012-0124:

http://www.metasploit.com/modules/exploit/windows/misc/hp_dataprotector_new_folder
https://community.rapid7.com/community/metasploit/blog/2012/07/06/an-example-of-egghunting-to-exploit-cve-2012-0124

In fact, the vulnerability exploited is an instance of CVE-2012-0123 and
CVE-2012-0121:

* CVE-2012-0123:  http://dvlabs.tippingpoint.com/advisory/TPTI-12-06

This vulnerability allows remote attackers to execute arbitrary code on
vulnerable installations of Hewlett-Packard Data Protector.
Authentication is not required to exploit this vulnerability.

The specific flaw exists within the dpwintdb.exe process which listens
by default on TCP port 3817. When parsing data within a DtbClsAddObject
request, the process copies data from the network into a fixed-length
buffer on the stack via an unchecked loop. This can be leveraged by
attackers to execute arbitrary code under the context of the SYSTEM user.


* CVE-2012-0121: http://www.zerodayinitiative.com/advisories/ZDI-12-097/

This vulnerability allows remote attackers to execute arbitrary code on
vulnerable installations of HP Data Protector Express. Authentication is
not required to exploit this vulnerability. User interaction is not
required to exploit this vulnerability.

The specific flaw exists within the dpwinsdr.exe process which listens
on TCP port 3817 by default. The process has insufficient bounds checking
on user-supplied data copied to a fixed-length buffer on the stack.
Remote, unauthenticated attackers can exploit this vulnerability by
sending malformed opcode 0x320 message packets to the target, which could
ultimately lead to arbitrary code execution under the context of the SYSTEM
user.


* Why is an instance of CVE-2012-0123?
======================================

Really, the handler of the operation "new folder" uses DtbClsAddObject to
create the new dir, where in fact, overflow happens.

The handler for the new folder operation can be found on dpwindtb.dll:

int __cdecl sub_1000C750(int a1, int a2, int a3, int a4, int a5)
{
  int v5; // ebx@1
  int result; // eax@1
  int v7; // ebx@3
  int v8; // eax@3
  int v9; // ecx@3
  int v10; // edx@3
  int v11; // [sp+Ch] [bp-24h]@3
  int v12; // [sp+10h] [bp-20h]@3
  int v13; // [sp+14h] [bp-1Ch]@3
  int v14; // [sp+18h] [bp-18h]@3
  char v15; // [sp+1Ch] [bp-14h]@2

  DtbClsByteOrder_ObjId(a5 + 28);
  DtbClsByteOrder_DTBOBJECT(a5 + 48);
  v5 = *(_DWORD *)(a5 + 44);
  result = DtbClsCheckValidOptions(v5);
  if ( !result )
  {
    result = DtbClsGetRequest(a2, a3, *(_DWORD *)(a5 + 20), *(_DWORD *)(a5 + 24), &v15);
    if ( !result )
    {
      resource_lock_sub_10002414();
      v7 = DtbClsAddObject(&v15, a5 + 28, v5 | 0x80000000, a5 + 48, &v11); // Using the vulnerable DtbClsAddObject with controlled data.
      resource_unlock_sub_10002991();
      DtbClsPutRequest(&v15);
      v8 = v12;
      v9 = v13;
      *(_DWORD *)(a5 + 20) = v11;
      v10 = v14;
      *(_DWORD *)(a5 + 24) = v8;
      *(_DWORD *)(a5 + 28) = v9;
      *(_DWORD *)(a5 + 32) = v10;
      SvcSetCommandLength();
      DtbClsByteOrder_ObjId(a5 + 20);
      result = v7;
    }
  }
  return result;
}


The metasploit blog can be checked for a detailed analysis of the
overflowing loop also announced by the ZDI advisory:

https://community.rapid7.com/community/metasploit/blog/2012/07/06/an-example-of-egghunting-to-exploit-cve-2012-0124

* Why it's an instance of CVE-2012-0121?
========================================

Because the "new folder" operation is one of the operations handled by
the dpwindtb module => Data Protector Express Microsoft Windows Database
Service (x86).

All these operations are handled by the same SVC ID => 0x32020202 (not
only 0x320 really). (The SVC ID is part of the packet header).

BTW, the available service ids (svc ids) are:
30000000
32020202 => ZDI-2012-097
33040404 => ZDI-2012-096
34050505
35060606
36070707

In order to get the available services the SvcGetServiceInstance_0 function
provided by the dpwinsup.dll module. In this function, the a1 arg is the
SVCID requested, and off_102A13BC + 26120 points to the valid SVC ID's
table:

signed int __cdecl SvcGetServiceInstance_0(int a1, int a2)
{
  void *v2; // esi@1
  unsigned int v3; // eax@1
  char *v4; // ecx@1

  v2 = off_102A13BC;
  v3 = 0;
  v4 = (char *)off_102A13BC + 26120;
  while ( *(_DWORD *)v4 != a1 )
  {
    ++v3;
    v4 += 4;
    if ( v3 >= 0x40 )
      return 59;
  }
  *(_DWORD *)a2 = *((_DWORD *)off_102A13BC + 2 * v3 + 6594);
  *(_DWORD *)(a2 + 4) = *((_DWORD *)v2 + 2 * v3 + 6595);
  return 0;
}

So at runtime with the help of debugging:

102e8c88  30000000 32020202 33040404 35060606
102e8c98  34050505 36070707 00000000 00000000

* Aren't there other 0x320 requests which could be vulnerable:
==============================================================

Absolutly YES! There could be others, but I've not been able to find them
atm.

In order to understand which subtypes of "0x320" requests exists, one must
have into account how connections are managed by HP Data Protector
Express.

Connections are managed by the dpwinsup.dll module, specifically by the
function sub_10191140, A connection needs to send a hello packet, once
done, different job requests and ping requests can be launch from the
same connection (handled by the infinite loop):

int __cdecl sub_10191140(int a1, int a2)
{
  int v2; // esi@1
  int v3; // edi@1
  int v4; // eax@3
  int v5; // ebx@3
  int v6; // eax@4
  int v7; // eax@6
  int v8; // eax@20
  __int16 v10; // [sp+10h] [bp-14h]@6

  v2 = *(_DWORD *)(a2 + 8);
  v3 = *(_DWORD *)(a2 + 12);
  if ( SvcGetPointerEx(0, 0, (void *)0x40001, *(_DWORD *)(a2 + 8), *(void **)(a2 + 12), (int)&a2)
    || (Msg(6, "Ses: %s connection service for %h is now running", (unsigned int)"Server"), handle_hello_sub_1000D198(a2)) )
  {
LABEL_18:
    v4 = a2;
    goto LABEL_19;
  }
  v4 = a2;
  v5 = *((_DWORD *)off_102A13BC + 6744);
  if ( *(_DWORD *)(a2 + 2486) != 1 )
  {
LABEL_19:
    *(_DWORD *)(v4 + 2482) |= 8u;
    sub_10007D97(a2, 2);
    goto LABEL_20;
  }
  while ( 1 )
  {
    v6 = SvcWaitForRecv(v4 + 40, v5);
    if ( v6 )
    {
      if ( v6 != 47 )
      {
        if ( v6 == 52 )
          Msg(6, "Ses: Socket timeout error on %s connection %h, connection dropped (%e)", (unsigned int)"server");
        else
          Msg(6, "Ses: Socket error waiting on %s connection %h, connection dropped (%e)", (unsigned int)"server");
      }
      goto LABEL_18;
    }
    v4 = a2;
    if ( *(_DWORD *)(a2 + 2486) != 1 )
      goto LABEL_19;
    v7 = SvcRecv(a2 + 40, 20, &v10);
    if ( v7 )
    {
      if ( v7 != 47 )
        Msg(6, "Ses: Socket error receiving header on connection %h, connection dropped (%e)", v2);
      goto LABEL_18;
    }
    if ( v10 == 0x8451 )
    {
      j_requests_84_51_sub_10190F60(a2, &v10);
      goto LABEL_11;
    }
    if ( v10 != 0x8455 )
      break;
    ping_request_sub_1000BEBA(a2);
LABEL_11:
    v4 = a2;
    if ( *(_DWORD *)(a2 + 2486) != 1 )
      goto LABEL_19;
  }
  if ( v10 != 33878 )
    goto LABEL_18;
  sub_1000BBBD(a2);
LABEL_20:
  Msg(6, "Ses: %s connection service for %h is now stopped", (unsigned int)"Server");
  v8 = a2;
  if ( *(_DWORD *)(a2 + 2486) != 2 )
  {
    SvcReleaseSocket(a2 + 40);
    v8 = a2;
  }
  *(_DWORD *)(v8 + 2486) = 0;
  SvcPutPointerEx(0, 0, (void *)0x40001, *(_DWORD *)a2, *(void **)(a2 + 4), (int)&a2);
  sub_10006479(v2, v3);
  return 0;
}

The packets headers are of 0x14 bytes with the next layout:

4 bytes => Packet ID
	0x8454 => Hello packets
	0x8451 => Job requests
	0x8455 => Ping requests
4 bytes => SVC ID
4 bytes => CMD ID
4 bytes => Packet length
4 bytes => ??Unknown?? 0x000000 works well to request jobs.

Every SVC (a dll really), handle its own CMD ID's. The dpwinsup.dll provides
the SvcCallDriver which is the responsible of dinamically dispatch the job
to the correct module:

int __cdecl SvcCallDriver_0(int a1, int a2, int a3)
{
  int result; // eax@1

  result = SvcIsValidInstanceIocmd(a1, a2);
  if ( !result )
    result = (*(int (__cdecl **)(int, int, int))(a1 + 512))(a1, a2, a3);
  return result;
}

In order to find the CMD ID's valids for the SVC 0x32020202 (dpwindtb.dll)
the job handler from this module must be examined:

int __cdecl sub_1001BAC0(int a1, unsigned int a2, int a3)
{
  int result; // eax@5

  if ( a2 <= 0x1000003 )
  {
    if ( a2 == 0x1000003 )
      return sub_1001BA30(a1);
    if ( a2 == 0x1000001 )
      return 0;
    if ( a2 == 16777218 )
      return sub_1001BA90(*(_DWORD *)(a3 + 8), *(_DWORD *)(a3 + 12));
    return 3;
  }
  if ( a2 == 0x1040007 )
  {
    if ( *(_DWORD *)(SvcGetGlobalDataEx() + 7908) )
      sub_10002252();
    result = 0;
  }
  else
  {
    if ( a2 != 0x2000001 )
      return 3;
    result = SvcDispatchService();
  }
  return result;
}

As seen above, it makes use of the SvcDispatchService() api, provided
by dpwinsup.dll, which finally queries the next table of available methods
on dpwindtb.dll:

.data:100A25C4                 dd offset sub_10002905  ; CMD ID 0x1
.data:100A25C8                 dd offset sub_10001B2C  ; CMD ID 0x2
.data:100A25CC                 dd offset sub_10001E51
.data:100A25D0                 dd offset sub_1000163B
.data:100A25D4                 dd offset sub_10001F6E
.data:100A25D8                 dd offset sub_10001B9A  ; CMD ID 0x6 => AddObject (new folder, our case)
.data:100A25DC                 dd offset sub_10002581
.data:100A25E0                 dd offset sub_10001AD2
.data:100A25E4                 dd offset sub_100026DF
.data:100A25E8                 dd offset sub_100020C7
.data:100A25EC                 dd offset sub_10001F28
.data:100A25F0                 dd offset sub_10001235
.data:100A25F4                 dd offset sub_10001CBC
.data:100A25F8                 dd offset sub_1000227F
.data:100A25FC                 dd offset sub_1000141F
.data:100A2600                 dd offset sub_100013E3
.data:100A2604                 dd offset sub_10002AA4
.data:100A2608                 dd offset sub_10002937
.data:100A260C                 dd offset sub_10001BD6
.data:100A2610                 dd offset sub_10002A8B
.data:100A2614                 dd offset sub_10001735
.data:100A2618                 dd offset sub_100025EA
.data:100A261C                 dd offset sub_1000236A
.data:100A2620                 dd offset sub_1000291E
.data:100A2624                 dd offset sub_10001DB6
.data:100A2628                 dd offset sub_100012B7
.data:100A262C                 dd offset sub_100027C0
.data:100A2630                 dd offset sub_100020A4
.data:100A2634                 dd offset sub_100010B4
.data:100A2638                 dd offset sub_1000101E
.data:100A263C                 dd offset sub_100020E0
.data:100A2640                 dd offset sub_10001F64
.data:100A2644                 dd offset sub_100021FD
.data:100A2648                 dd offset sub_100018A2
.data:100A264C                 dd offset sub_100011B8
.data:100A2650                 dd offset sub_10002383
.data:100A2654                 dd offset sub_1000106E
.data:100A2658                 dd offset sub_1000233D
.data:100A265C                 dd offset sub_1000132A
.data:100A2660                 dd offset sub_100014E2
.data:100A2664                 dd offset sub_1000245F
.data:100A2668                 dd offset sub_10001F14
.data:100A266C                 align 10h
.data:100A2670                 dd offset sub_10001FFA
.data:100A2674                 dd offset sub_1000164F
.data:100A2678                 dd offset sub_1000247D
.data:100A267C                 dd offset sub_1000244B
.data:100A2680                 dd offset sub_10002473
.data:100A2684                 dd offset sub_10002563
.data:100A2688                 dd offset sub_100020B3
.data:100A268C                 dd offset sub_10002342
.data:100A2690                 dd offset sub_100023C9
.data:100A2694                 dd offset sub_100028E7
.data:100A2698                 dd offset sub_10001A69
.data:100A269C                 dd offset sub_10001CF3
.data:100A26A0                 dd offset sub_10002AEF
.data:100A26A4                 dd offset sub_100014B5
.data:100A26A8                 dd offset sub_10001DFC
.data:100A26AC                 dd offset sub_10001AFF
.data:100A26B0                 dd offset sub_10001F1E
.data:100A26B4                 dd offset sub_10001348
.data:100A26B8                 dd offset sub_10001BD1
.data:100A26BC                 dd offset sub_100023E7
.data:100A26C0                 dd offset sub_10001F55
.data:100A26C4                 dd offset sub_10002A3B
.data:100A26C8                 dd offset sub_10001BC2
.data:100A26CC                 dd offset sub_100019C4
.data:100A26D0                 dd offset sub_10001DC5
.data:100A26D4                 dd offset sub_10001F46
.data:100A26D8                 dd offset sub_1000103C
.data:100A26DC                 dd offset sub_10002469
.data:100A26E0                 dd offset sub_10001F05

* Aren't there other calls to DtbClsAddObject ?
===============================================

After inspecting xrefs to DtbClsAddObject from dpwindtb.dll the only reference
easily rechable from a job handler is the new folder case, but sure, other
references should be examined carefully, no luck atm. I tried also a
dynamic approach, debug using the original client, breakpoing the
DtbClsAddObject... no luck atm.

* Bindiffing
============

1) Bindiffing of the windtb.dll module has been conducted, there are
mainly two differences:

* The method used for the AddFolder (our exploit, maybe aaron was able
to bypass authentication?? I've tried but no success atm)!!! grrrr BTW,
the login is handled by the routine sub_1002DD30 in dpwindtb.dll, which
uses dtbclslogin (http://www.zerodayinitiative.com/advisories/ZDI-10-174/).
* The method used for the Upgrade (cmd ID => 0x42, checks for product
activation, since Im working with the trial, no luck testint this case.

2) Also bindiffing of the dpwinods.dll module has been conducted ( 0x330 requests service handler ): all matches
with similarity 1.0
