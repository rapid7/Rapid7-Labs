---
title: Exim EHLO crash bug
author: wchen-r7
score: 4
topic_attacker_value: 2.5
topic_exploitability: 3.5
topic_disclosure_date: '2019-09-27T21:15:00'
created: '2019-10-04T22:50:37.399381'
revision_date: '2020-02-13T17:12:01.782872'
assessment_id: b3e537c4-79cf-44b2-ae15-4d7e5b7baa01
topic_id: 862dfb64-ee07-4f1f-b5f3-8f2c3a560a5f
topic_short_id: T6aghc4yib
topic_slug: exim-ehlo-crash-bug
akb_topic_url: https://attackerkb.com/topics/T6aghc4yib/exim-ehlo-crash-bug
akb_assessment_url: https://attackerkb.com/topics/T6aghc4yib/exim-ehlo-crash-bug#b3e537c4-79cf-44b2-ae15-4d7e5b7baa01
author_ratings:
  attacker-value: 3
  confidence-in-ratings: 5
  exploitability: 3
  urgent-to-patch: 5
  used-successfully: 3
---

# Exim EHLO crash bug

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/T6aghc4yib/exim-ehlo-crash-bug#b3e537c4-79cf-44b2-ae15-4d7e5b7baa01).*

---

# CVE-2019-16928: Exim EHLO Heap Overflow Vulnerability

## Description

[Exim](https://www.exim.org/) is an open source mail transfer agent (MTA) designed for receiving, routing, and delivering email messages. It is mostly installed on Unix-like systems, sometimes Microsoft Windows using Cygwin. [As of 2019](http://www.securityspace.com/s_survey/data/man.201907/mxsurvey.html), approximately 57% of the publicly reachable mail servers on the Internet ran Exim, therefore it is quite a popular software. 

A vulnerability was found in Exim by a Chinese security team called [QAX A-Team](https://github.com/QAX-A-Team), specifically related to the string_vformat() function not resizing a heap buffer correctly, resulting a heap overflow. Proof-of-concept is publicly available, and remote code execution could be possible. Since Exim has been widely used on the Internet, [media attention](https://threatpost.com/critical-exim-flaw-opens-servers-to-remote-code-execution/148773/) for the vulnerability was also high. More details about the potential impact can be found the [Project Sonar research](https://blog.rapid7.com/2019/09/10/cve-2019-15846-privileged-remote-code-execution-vulnerability-in-the-exim-mailer-what-you-need-to-know/) from Rapid7.

## Technical Details

### The Bug Report

Initial information about the vulnerability can be traced to a ticket on Exim's BugZilla system, also known as [#2449](https://bugs.exim.org/show_bug.cgi?id=2449). In there, we can see that the vulnerability is described as a heap overflow in the string_vformat() function, which can be triggered with a EHLO command. A Python proof-of-concept is also available.

A commit for the fix can also be found under the exim-4.92.2+fixes branch, which is a simple one-line change to the size argument for the `gstring_grow` in file string.c:

```c
// string.c:1593	
gstring_grow(g, g->ptr, width - (lim - g->ptr)); // Vulnerable version
gstring_grow(g, g->ptr, width);                  // Patched version
```

Now that the bug seems pretty legit, let's go ahead and set up a box for debugging purposes.

## Vulnerable Setup

The Exim source can be downloaded and compiled on a Unix-based machine. In my case, I set up a Ubuntu 18 box, with the following prepared:

```bash
sudo apt update && apt install build-essential clang libdb-dev libperl-dev libsasl2-dev libxt-dev libxaw7-dev
```

And then I got the 4.92.2 version:

```bash
wget http://exim.mirror.colo-serv.net/exim/exim4/old/exim-4.92.2.tar.xz
```

To build Exim, a Makefile needs to be created, and the easier way is by doing this in the Exim folder (also, remember to set the EXIM_USER option in the file):

```bash
cp src/EDITME Local/Makefile && cp exim_monitor/EDITME Local/eximon.conf
```

For debugging purposes, I compiled Exim as a "PIE" binary with AddressSanitizer:

```bash
CC=clang CFLAGS+=" -g -fPIC -fsanitize=address" ASAN_LIBS+="-static-libasan" ASAN_FLAGS+="-fsanitize=address -fno-omit-frame-pointer" FULLECHO='' LFLAGS+="-L/usr/lib/llvm-6.0/lib/clang/6.0.0/lib/linux/ -lasan -pie" ASAN_OPTIONS=detect_leaks=0:symbolize=1 LDFLAGS+=" -lasan -pie -ldl -lm -lcrypt" LD_PRELOAD+="/usr/lib/gcc/x86_64-linux-gnu/7/libasan.so" LIBS+="-lasan -pie" make -e clean all
```

Note: For some reason, I couldn't really compile Exim with GCC with AddressSanitizer, and clang ended up being a much easier choice.

After that, the Exim binary can be found in the `build-Linux-x86_64` directory. Typically, I prefer to verify that I compiled something correctly (such as PIE and ASAN states), so in this case I used [pwntools](https://github.com/Gallopsled/pwntools) to check this:

```bash
$ python pwntools/pwnlib/commandline/checksec.py exim-4.92.2/build-Linux-x86_64/exim
[*] '/home/wchen/Desktop/exim-4.92.2/build-Linux-x86_64/exim'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    ASAN:     Enabled
```

And finally, start Exim as a foreground process:

```bash
sudo build-Linux-x86_64/exim -bd -d
```

### Code Analysis

Looking at the bug report, the patched code actually comes from a function called `string_vformat`. The purpose of it is to build or append to a custom string object that can automatically grow if necessary, and it is declared this way:

```c
gstring* string_vformat(gstring * g, BOOL extend, const char *format, va_list ap)
```

The `gstring` argument is a custom structure that is defined in the structs.h file as follows (Line 29):

```c
gstring structure (structs.h:29)

typedef struct gstring {
  int    size;        /* Current capacity of string memory */
  int    ptr;        /* Offset at which to append further chars */
  uschar * s;        /* The string memory */
} gstring;
```

The second argument for `string_vformat` is a boolean called `extend`. This is simply a flag that indicates whether the program wants the gstring to grow or not. And finally, there's a `format` and `va_list` argument, which is similar to how `sprint` works.

The second argument is an important piece to the puzzle, because the vulnerable code requires it to be true in order to trigger. In this case, the `string_vformat` function needs to grow gstring in order to make room for the input that it's handling, and then the gstring will tell the function which index to begin saving the new input. This idea can be demonstrated as below:

First, let's say we have allocated a 10-byte buffer. Visually, the 00 (null byte) represents free space:

```
Index:   0  1  2  3  4  5  6  7  8  9
Buffer: [00 00 00 00 00 00 00 00 00 00]
```

Initially, let's also say we already have some data in the buffer, a few "A" characters. At this point, the offset at which to append further chars would be index 5:

```
                        * Offset starts at 5
Index:   0  1  2  3  4  5  6  7  8  9
Buffer: [41 41 41 41 41 00 00 00 00 00]
```

Now, we have a scenario where the new input is a bunch of "B"s that is also 10-byte long:

```
char* input = "BBBBBBBBBB"; // In hex, these are 42 42 42...
```

To put that in the buffer, we need to grow it. So in theory what is new size for the adjusted buffer? The math is:

```c
strlen(input) + offset;
```

After growing the buffer, it should look like this:

```
                        * 5 = offset value
Index:   0  1  2  3  4  5  6  7  8  9  10 11 12 13 14
Buffer: [41 41 41 41 41 00 00 00 00 00 00 00 00 00 00]
```

And finally, we have enough space to store the input:

```
                        * 5 = offset value
Index:   0  1  2  3  4  5  6  7  8  9  10 11 12 13 14
Buffer: [41 41 41 41 41 42 42 42 42 42 42 42 42 42 42]
```

Knowing this concept, it is much easier to understand the vulnerability. The reason of the overflow is because the size calculation is wrong. The `gstring_grow` function in Exim simply does not grow enough for gstring, as a result when it is storing the user supplied input from the EHLO command, it overflows, kind of like the following:

```
                        * 5 = offset value
Index:   0  1  2  3  4  5  6  7  8  9  10 11 12 13 14
Buffer: [41 41 41 41 41 42 42 42 42 42 42 42 42 42 42] 42 42 42 42 42 ...
                                                       ^ Overflow
```

Although the vulnerability requires additional buffer growth, not every call to `string_vformat` sets the `extend` flag too true. Looking around, it looks like there are many possible ways to trigger it:

* There are at least five functions that directly call `string_vformat` with the `extend` flag to true.
* One of them is called `string_fmt_append`, and this function is used by about 56 other places through out the code base.

The scope here would be too time consuming to determine the actual vulnerable path, but we can narrow this down by a lot. All we need to do is figure out when the input enters the code, until when the vulnerable code triggers, then we can look into that code path:

```
Input ---> Code path to be investigated ---> string_vformat with extend argument to TRUE
```

In the Exim log, we can get a hint on where the input sort of begins:

```
70289 SMTP>> 220 ubuntu ESMTP Exim 4.92.2 Fri, 04 Oct 2019 09:21:46 -0700
70289 Process 70289 is ready for new message
70289 smtp_setup_msg entered
70289 SMTP<< EHLO AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Notice that we see a "smtp_setup_msg" message first, and then the EHLO with our input. So if we search for that message and find the function printing it, we have a starting point:

```c
// smtp_in.c:3891
int smtp_setup_msg(void)
{
int done = 0;
BOOL toomany = FALSE;
BOOL discarded = FALSE;
BOOL last_was_rej_mail = FALSE;
BOOL last_was_rcpt = FALSE;
void *reset_point = store_get(0);

DEBUG(D_receive) debug_printf("smtp_setup_msg entered\n");
  // ... code ...
```

So now, I guess we are looking for this type of code path:

```
smtp_setup_msg() ---> Code path unknown --> string_vformat(gs, TRUE, format, ap);
```

This is the very vague version, but in reality the unknown code path is often a rabbit hole. A large codebase such as Exim definitely took me a lot of time to clean up the noises. One way to reverse engineer how point A might get to point B is by using some kind of flow graph. Honestly, I don't know if there is a good one for C/C++ source code, but you certainly do this with a plugin called [AlleyCat](https://github.com/devttys0/ida/tree/master/plugins/alleycat) from IDA Pro.

This is the graph I got that that shows how `smtp_setup_msg()` could get to `string_vformat`:

![alleycat_graph](https://user-images.githubusercontent.com/51334915/66244626-e46ae780-e6f8-11e9-9c92-673bfaf2bc13.png)

Looking at this graph is kind of like finding a needle in a haystack, but if you use it like a map to aid code analysis, you're less likely to get lost in the rabbit hole. What's really funny is that out of this complex map, let me show you the actual path to trigger the vulnerable code:

![found_path](https://user-images.githubusercontent.com/51334915/66244620-e0d76080-e6f8-11e9-981a-562af223be9a.png)

In the end, we only need to look at three functions:

1. smtp_setup_msg() in smtp_in.c
2. string_fmt_append in string.c
3. string_vformat() in string.c (the vulnerable function)

In order to trigger step 2 (the string_fmt_append function), a `user_msg` variable also needs to be null. The `user_msg` is set from a function called `acl_check()` (in acl.c). The null return value indicates the check returns OK, so that means our HELO needs to fail the ACL check.

Another requirement of the vulnerability is that if Exim is able to look up and resolve an IP address, then it would not trigger. For testing purposes, the easier way to clear your /etc/resolve.conf.

And finally, now with a good understanding of the vulnerable code path, we can verify all this with AddressSanitizer, and this concludes our analysis for CVE-2019-16928:

```
==56449==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x62500000c598 at pc 0x7f8cd18048f9 bp 0x7ffe0bb4dea0 sp 0x7ffe0bb4d630
WRITE of size 11294 at 0x62500000c598 thread T0
    #0 0x7f8cd18048f8 in __interceptor_vsprintf (/usr/lib/x86_64-linux-gnu/libasan.so.4+0x9e8f8)
    #1 0x7f8cd1804c86 in __interceptor_sprintf (/usr/lib/x86_64-linux-gnu/libasan.so.4+0x9ec86)
    #2 0x558f99fc796c in string_vformat /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/string.c:1602
    #3 0x558f99df7ee5 in debug_vprintf /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/debug.c:240
    #4 0x558f99df6a3a in debug_printf /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/debug.c:165
    #5 0x558f99ebeb20 in host_build_sender_fullhost /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/host.c:662
    #6 0x558f99f9801a in smtp_setup_msg /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/smtp_in.c:4178
    #7 0x558f99df0236 in handle_smtp_call /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/daemon.c:504
    #8 0x558f99dec11f in daemon_go /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/daemon.c:2057
    #9 0x558f99e5b0e9 in main /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/exim.c:4670
    #10 0x7f8cd0386b96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
    #11 0x558f99dc05b9 in _start (/home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/exim+0x1125b9)

0x62500000c598 is located 0 bytes to the right of 9368-byte region [0x62500000a100,0x62500000c598)
allocated by thread T0 here:
    #0 0x7f8cd1844b50 in __interceptor_malloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdeb50)
    #1 0x558f99fbb78b in store_malloc_3 /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/store.c:544
    #2 0x558f99fba87c in store_get_3 /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/store.c:167
    #3 0x558f99fbd6f1 in store_newblock_3 /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/store.c:511
    #4 0x558f99fcaab0 in gstring_grow /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/string.c:1163
    #5 0x558f99fc781b in string_vformat /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/string.c:1597
    #6 0x558f99df7ee5 in debug_vprintf /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/debug.c:240
    #7 0x558f99df6a3a in debug_printf /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/debug.c:165
    #8 0x558f99ebeb20 in host_build_sender_fullhost /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/host.c:662
    #9 0x558f99f9801a in smtp_setup_msg /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/smtp_in.c:4178
    #10 0x558f99df0236 in handle_smtp_call /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/daemon.c:504
    #11 0x558f99dec11f in daemon_go /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/daemon.c:2057
    #12 0x558f99e5b0e9 in main /home/sinn3r/Desktop/exim-4.92.2/build-Linux-x86_64/exim.c:4670
    #13 0x7f8cd0386b96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)

SUMMARY: AddressSanitizer: heap-buffer-overflow (/usr/lib/x86_64-linux-gnu/libasan.so.4+0x9e8f8) in __interceptor_vsprintf
Shadow bytes around the buggy address:
  0x0c4a7fff9860: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c4a7fff9870: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c4a7fff9880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c4a7fff9890: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c4a7fff98a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c4a7fff98b0: 00 00 00[fa]fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c4a7fff98c0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c4a7fff98d0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c4a7fff98e0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c4a7fff98f0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c4a7fff9900: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==56449==ABORTING
```

## References

* [Exim off by one RCE exploiting CVE-2018-6789](https://devco.re/blog/2018/03/06/exim-off-by-one-RCE-exploiting-CVE-2018-6789-en/) by Meh
* [Fuzzing arbitrary functions in elf binaries](https://blahcat.github.io/2018/03/11/fuzzing-arbitrary-functions-in-elf-binaries/) by hugsy
* [Exim CVE-2019-16928 Bug Report](https://bugs.exim.org/show_bug.cgi?id=2449)
* [The patch diff for CVE-2019-16928](https://github.com/Exim/exim/commit/478effbfd9c3cc5a627fc671d4bf94d13670d65f#diff-2df79c106af94fb3d05bc3f75d7f2abbL1133-L1590)
* [Exim4 string_format Heap Buffer Overflow Exploit Example](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/smtp/exim4_string_format.rb)
* [Exim Archive](http://exim.mirror.colo-serv.net/exim/exim4/old/)
* [Example of building and install Exim](https://www.lisenet.com/2015/compile-and-install-exim-from-source-with-ldap-and-mysql-lookup-support-on-ubuntu-14-04/)
