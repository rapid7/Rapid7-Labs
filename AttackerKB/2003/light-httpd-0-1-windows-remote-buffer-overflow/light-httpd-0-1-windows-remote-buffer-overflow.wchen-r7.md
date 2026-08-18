---
title: Light HTTPd 0.1 (Windows) - Remote Buffer Overflow
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2003-03-31T05:00:00'
created: '2019-09-12T18:07:09.847285'
revision_date: '2020-02-13T17:12:19.999431'
assessment_id: 41074e5b-71bf-4395-b100-54aaabf75de7
topic_id: 8be90e5f-0a56-48b2-b8a1-f0cf45b12ca5
topic_short_id: sRHAhXcB9W
topic_slug: light-httpd-0-1-windows---remote-buffer-overflow
akb_topic_url: https://attackerkb.com/topics/sRHAhXcB9W/light-httpd-0-1-windows---remote-buffer-overflow
akb_assessment_url: https://attackerkb.com/topics/sRHAhXcB9W/light-httpd-0-1-windows---remote-buffer-overflow#41074e5b-71bf-4395-b100-54aaabf75de7
---

# Light HTTPd 0.1 (Windows) - Remote Buffer Overflow

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/sRHAhXcB9W/light-httpd-0-1-windows---remote-buffer-overflow#41074e5b-71bf-4395-b100-54aaabf75de7).*

---

```
start    end        module name
00400000 0041a000   lhttpd   C:\Documents and Settings\Administrator\My Documents\Downloads\ad9f3af85dc51499f7d252eb11bac5a2-lhttpd0.1-win\lhttpd\lhttpd.exe
662b0000 66308000   hnetcfg  C:\WINDOWS\system32\hnetcfg.dll
71a50000 71a8f000   mswsock  C:\WINDOWS\system32\mswsock.dll
71a90000 71a98000   wshtcpip C:\WINDOWS\System32\wshtcpip.dll
71aa0000 71aa8000   WS2HELP  C:\WINDOWS\system32\WS2HELP.dll
71ab0000 71ac7000   WS2_32   C:\WINDOWS\system32\WS2_32.dll
71ad0000 71ad9000   WSOCK32  C:\WINDOWS\system32\WSOCK32.DLL
76390000 763ad000   IMM32    C:\WINDOWS\system32\IMM32.DLL
77c10000 77c68000   msvcrt   C:\WINDOWS\system32\msvcrt.dll
77dd0000 77e6b000   ADVAPI32 C:\WINDOWS\system32\ADVAPI32.dll
77e70000 77f02000   RPCRT4   C:\WINDOWS\system32\RPCRT4.dll
77f10000 77f59000   GDI32    C:\WINDOWS\system32\GDI32.dll
77fe0000 77ff1000   Secur32  C:\WINDOWS\system32\Secur32.dll
7c800000 7c8f6000   kernel32 C:\WINDOWS\system32\kernel32.dll
7c900000 7c9af000   ntdll    C:\WINDOWS\system32\ntdll.dll
7e410000 7e4a1000   USER32   C:\WINDOWS\system32\USER32.DLL
```


Found sequences (All Modules)

```
Address    Disassembly                               Comment                                   Module Name
00401000   JMP SHORT lhttpd.00401012                 (Initial CPU selection)                   C:\Documents and Settings\Administrator\My Documents\Downloads\ad9f3af85dc51499f7d252eb11bac5a2-lhttpd0.1-win\lhttpd\lhttpd.exe
662B1000   TEST AL,7C                                (Initial CPU selection)                   C:\WINDOWS\system32\hnetcfg.dll
662EB24F   JMP ESP                                                                             C:\WINDOWS\system32\hnetcfg.dll
71A51000   MOVS BYTE PTR ES:[EDI],BYTE PTR DS:[ESI]  (Initial CPU selection)                   C:\WINDOWS\system32\mswsock.dll
71A91000   SBB BL,BYTE PTR DS:[ESI]                  (Initial CPU selection)                   C:\WINDOWS\System32\wshtcpip.dll
71A91C8B   JMP ESP                                                                             C:\WINDOWS\System32\wshtcpip.dll
71AA1000   MOV ECX,A877DD7C                          (Initial CPU selection)                   C:\WINDOWS\system32\WS2HELP.dll
71AB1000   OUT DX,AL                                 (Initial CPU selection)                   C:\WINDOWS\system32\WS2_32.dll
71AD1000   ADC EAX,DWORD PTR ES:[ECX+8017E97C]       (Initial CPU selection)                   C:\WINDOWS\system32\WSOCK32.DLL
76391000   MOV EDX,A877DD7F                          (Initial CPU selection)                   C:\WINDOWS\system32\IMM32.DLL
77C11000   MOV BYTE PTR DS:[EAX+EAX*4+90FE017C],BL   (Initial CPU selection)                   C:\WINDOWS\system32\msvcrt.dll
77DD1000   SUB DWORD PTR DS:[ESI],EDX                (Initial CPU selection)                   C:\WINDOWS\system32\ADVAPI32.dll
77DEF049   JMP ESP                                                                             C:\WINDOWS\system32\ADVAPI32.dll
77DF965B   JMP ESP                                                                             C:\WINDOWS\system32\ADVAPI32.dll
77E18063   JMP ESP                                                                             C:\WINDOWS\system32\ADVAPI32.dll
77E23B63   JMP ESP                                                                             C:\WINDOWS\system32\ADVAPI32.dll
77E42A9F   JMP ESP                                                                             C:\WINDOWS\system32\ADVAPI32.dll
77E71000   MOV DH,79                                 (Initial CPU selection)                   C:\WINDOWS\system32\RPCRT4.dll
77E8560A   JMP ESP                                                                             C:\WINDOWS\system32\RPCRT4.dll
77E9025B   JMP ESP                                                                             C:\WINDOWS\system32\RPCRT4.dll
77F11000   INC ESI                                   (Initial CPU selection)                   C:\WINDOWS\system32\GDI32.dll
77F31D2F   JMP ESP                                                                             C:\WINDOWS\system32\GDI32.dll
77FE1000   PUSH EDI                                  (Initial CPU selection)                   C:\WINDOWS\system32\Secur32.dll
7C801000   INT 81                                    (Initial CPU selection)                   C:\WINDOWS\system32\kernel32.dll
7C86467B   JMP ESP                                                                             C:\WINDOWS\system32\kernel32.dll
7C901000   MOV ECX,DWORD PTR FS:[18]                 (Initial CPU selection)                   C:\WINDOWS\system32\ntdll.dll
7E411000   SALC                                      (Initial CPU selection)                   C:\WINDOWS\system32\USER32.DLL
7E429353   JMP ESP                                                                             C:\WINDOWS\system32\USER32.DLL
7E4456F7   JMP ESP                                                                             C:\WINDOWS\system32\USER32.DLL
7E455AF7   JMP ESP                                                                             C:\WINDOWS\system32\USER32.DLL
7E45B310   JMP ESP                                                                             C:\WINDOWS\system32\USER32.DLL
```

Dump:

```
00dfbceb 90 90 90 90 90 90 90  .......
00dfbcf2 90 90 90 90 90 90 90  .......
00dfbcf9 90 90 90 90 90 20 2d  ..... -
00dfbd00 20 43 6f 6e 6e 65 63   Connec
00dfbd07 74 69 6f 6e 20 66 72  tion fr
00dfbd0e 6f 6d 20 31 30 2e 30  om 10.0
00dfbd15 2e 31 2e 37 36 2c 20  .1.76,
00dfbd1c 72 65 71 75 65 73 74  request
00dfbd23 20 3d 20 22 47 45 54   = "GET
00dfbd2a 20 2f 90 90 90 90 90   /.....
00dfbd31 90 90 90 90 90 90 90  .......
00dfbd38 90 90 90 90 90 90 90  .......
00dfbd3f 90 90 90 90 90 90 90  .......
00dfbd46 90 90 90 90 90 90 90  .......
```


In function serveconnection(), protocol.c:

```
  Log("Connection from %s, request = \"GET %s\"", inet_ntoa(sa.sin_addr), ptr);
```

The Log() function comes from util.c:

```
	void Log(char *format, ...)
	{
		FILE *logfile;
		time_t t;
		struct tm *tm;
		char temp[200], temp2[200], logfilename[255];
		char datetime[] = "[%d.%m.%Y] [%H:%M.%S]";
		char datetime_final[128];
		va_list ap;

		va_start(ap, format);		// format it all into temp
		vsprintf(temp, format, ap);
```
