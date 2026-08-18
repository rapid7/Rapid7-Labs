---
title: Siemens Solid Edge WebPartHelper ActiveX Remote Code Execution
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
created: '2019-09-12T18:07:42.869118'
revision_date: '2020-02-13T17:12:11.849765'
assessment_id: e76aacc7-245b-42ad-9194-6f55c57c1332
topic_id: 42d17cb0-fa17-452e-a83b-20f2c3c10da3
topic_short_id: Fueokinchu
topic_slug: siemens-solid-edge-webparthelper-activex-remote-code-execution
akb_topic_url: https://attackerkb.com/topics/Fueokinchu/siemens-solid-edge-webparthelper-activex-remote-code-execution
akb_assessment_url: https://attackerkb.com/topics/Fueokinchu/siemens-solid-edge-webparthelper-activex-remote-code-execution#e76aacc7-245b-42ad-9194-6f55c57c1332
---

# Siemens Solid Edge WebPartHelper ActiveX Remote Code Execution

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/Fueokinchu/siemens-solid-edge-webparthelper-activex-remote-code-execution#e76aacc7-245b-42ad-9194-6f55c57c1332).*

---

Vulnerability:

the WebPartHelper Class offers the OpenInEditor() method, see typelib:

...
  /* DISPID=8 */
function OpenInEditor(
        /* VT_VARIANT [12] [in] */ $URL
        )
{
}
...

By passing an null session share path to the URL argument of this method
is possible to launch an arbitrary executable.

This is because of a ShellExecuteExW() call inside RFMSsvs.dll


Analysis:

The ShellExecuteW is this one:

.text:100E9F07 loc_100E9F07:                           ; CODE XREF: JShellExecuteEx+1B6j
.text:100E9F07                 push    esi             ; pExecInfo
.text:100E9F08                 call    ds:ShellExecuteExW

Where the pExecInfo can be partially controlled by the user:

.text:100E9EDE                 call    ds:??BGUserText@@QBEPB_WXZ ; GUserText::operator wchar_t const *(void)
.text:100E9EE4                 mov     [esi+10h], eax

But just the esi+10h field of a SHELLEXECUTEINFO can be controlled:

typedef struct _SHELLEXECUTEINFO {
  DWORD     cbSize;
  ULONG     fMask;
  HWND      hwnd;
  LPCTSTR   lpVerb;
  LPCTSTR   lpFile; <== esi + 10h
  LPCTSTR   lpParameters;
  LPCTSTR   lpDirectory;
  int       nShow;
  HINSTANCE hInstApp;
  LPVOID    lpIDList;
  LPCTSTR   lpClass;
  HKEY      hkeyClass;
  DWORD     dwHotKey;
  union {
    HANDLE hIcon;
    HANDLE hMonitor;
  } DUMMYUNIONNAME;
  HANDLE    hProcess;
} SHELLEXECUTEINFO, *LPSHELLEXECUTEINFO;

So just the lpFile can be controlled. It doesn't allow to an awesome exploitation, but there are cases on metasploit.

Just use a WebDav to simulate a SMB resource, the target machine should have enabled the WebClient service (WebDAV Mini-Redirector). And
execute a file via an UNC path. Anyway exploitation limited to machines with WebClient enabled (Windows XPSP3 enabled by default).
