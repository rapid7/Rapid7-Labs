---
title: The LZO/LZ4 Integer Overflow Summary
author: wchen-r7
score: 2
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2014-07-03T04:22:00'
created: '2019-09-12T18:07:43.476949'
revision_date: '2020-10-19T23:10:35.852092'
assessment_id: 28484fad-bd7f-4673-9c2c-264c2218ad7e
topic_id: ab7462e1-84b6-45b0-8d93-6857fb1ce045
topic_short_id: 7IAOfmR8XA
topic_slug: the-lzo-lz4-integer-overflow-summary
akb_topic_url: https://attackerkb.com/topics/7IAOfmR8XA/the-lzo-lz4-integer-overflow-summary
akb_assessment_url: https://attackerkb.com/topics/7IAOfmR8XA/the-lzo-lz4-integer-overflow-summary#28484fad-bd7f-4673-9c2c-264c2218ad7e
---

# The LZO/LZ4 Integer Overflow Summary

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/7IAOfmR8XA/the-lzo-lz4-integer-overflow-summary#28484fad-bd7f-4673-9c2c-264c2218ad7e).*

---

On Jun 26th, Don A. Bailey of Security Mouse published a blog detailing an integer overflow within
the LZO algorithm, specifically the LZ4 variant. The writeup can be found here:

http://blog.securitymouse.com/2014/06/raising-lazarus-20-year-old-bug-that.html

PoC Example (Windows 32-bit):

```
#include "lz4.h"

char output[20<<20];
char input[20<<20];
int main(int argc, char* argv[]) {
  input[0] = 0x0F;
  input[1] = 0x00;
  input[2] = 0x00;
  for(int i = 3; i < 16800000; i++)
    input[i] = 0xff;
  LZ4_uncompress(input, output, 20<<20);
  return 0;
}
```

The LZ4 algorithm is vulnerable but in the real world no implementations are because either the
necessary vulnerable conditions aren't dialed in correctly, or there is something else in place
(in the software or by operating system) that prevents the bug from exploitation. The flaw
requires the following conditions:

* Must be in a 32-bit environment, which means all servers are safe from this issue.
* The attacker need to forge a special compressed block to overflow a 32-bit address space and
  cause the decoding process to overflow, but it can only be done if the compressed block is
  something like 16MB or more. Some real-world implementations:
  	* Legacy LZ4 file format is limited to 8MB, newer format is at 4MB.
  	* ZFS = 128KB
  	* zram = 4KB
  	* Linux kernel = 8MB (uses LZ4 legacy)
  	* Antivirus unpacking uses the official documented LZ4 (4MB max, 8MB if legacy format)
  	* The latest lzo.c in FFmpeg is set at (10*1024*1024) + 16 (that's 10MB + 16 bytes), and is allocated
  	  on the heap. However, matroskadec.c uses av_lzo1x_decode() with its own implementation and as
  	  far as I can tell there is no hard size limit.
* The attack is most likely local

From the attacker's perspective, it's difficult to find apps out there that are actually vulnerable,
because so far we have not found one that exceeds 10MB, and we need something like 16MB. It's even
more difficult to find them exploitable because of other memory corruption mitigations supported by
modern operating systems.


The fix in LZ4 can be found here (there is also a testing tool in fuzz.c):
https://github.com/Cyan4973/lz4/commit/da5373197e84ee49d75b8334d4510689731d6e90
