private rule SUS_Exceptions_Jan24 {
    meta:
        description = "Detects unique exception strings from AgentTesla final payload in decompiled code and process memory"
        author = "Matt Green - @mgreen27"
        date = "2024-01-18"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "ebe2a77dab04458defd4d8f7760abda79a507ab0168d68a2930f9d7b1120127e"
        
    strings:
        $exception1 = "Unknow database format" wide fullword
        $exception2 = "Size of the SerializedPropertyStore is less than" wide
        $exception3 = "Version is not equal to " wide
        $exception4 = "Size of the StringName is less than 9" wide
        $exception5 = "Size of the StringName is not equal to " wide
        $exception6 = "Size of the NameSize is not equal to " wide

    condition:
        4 of ($exception*)
}

private rule SUS_Windows_Vault_Guids_Jan24 {
    meta:
        description = "Detects Windows Vault GUID strings observed in AgentTesla payload."
        author = "Matt Green - @mgreen27"
        date = "2024-01-18"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "ebe2a77dab04458defd4d8f7760abda79a507ab0168d68a2930f9d7b1120127e"
        
    strings:
        $s1 = "2F1A6504-0641-44CF-8BB5-3612D865F2E5" wide 	//Windows Secure Note
        $s2 = "3CCD5499-87A8-4B10-A215-608888DD3B55" wide 	//Windows Web Password Credential
        $s3 = "154E23D0-C644-4E6F-8CE6-5069272F999F" wide 	//Windows Credential Picker Protector
        $s4 = "4BF4C442-9B8A-41A0-B380-DD4A704DDB28" wide 	//Web Credentials
        $s5 = "77BC582B-F0A6-4E15-4E80-61736B6F3B29" wide 	//Windows Credentials
        $s6 = "E69D7838-91B5-4FC9-89D5-230D4D4CC2BC" wide 	//Windows Domain Certificate Credential
        $s7 = "3E0E35BE-1B77-43E7-B873-AED901B6275B" wide 	//Windows Domain Password Credential
        $s8 = "3C886FF3-2669-4AA2-A8FB-3F6759A77548" wide 	//Windows Extended Credential

    condition:
        all of them
}

private rule SUS_Browser_References_Jan24 {
    meta:
        description = "Detects unique strings observed in AgentTesla browser stealer module in decompiled code and process memory"
        author = "Matt Green - @mgreen27"
        date = "2024-01-18"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "ebe2a77dab04458defd4d8f7760abda79a507ab0168d68a2930f9d7b1120127e"
        
    strings:
        $browser01 = "7Star\\7Star\\User Data" wide
        $browser02 = "CocCoc\\Browser\\User Data" wide
        $browser03 = "Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer" wide
        $browser04 = "\\Thunderbird\\" wide
        $browser05 = "\\K-Meleon\\" wide
        $browser06 = "360Chrome\\Chrome\\User Data" wide
        $browser07 = "uCozMedia\\Uran\\User Data" wide
        $browser08 = "\\Mozilla\\SeaMonkey\\" wide
        $browser09 = "Orbitum\\User Data" wide
        $browser10 = "CentBrowser\\User Data" wide
        $browser11 = "Elements Browser\\User Data" wide
        $browser12 = "CatalinaGroup\\Citrio\\User Data" wide
        $browser13 = "Yandex\\YandexBrowser\\User Data" wide
        $browser14 = "liebao\\User Data" wide
        $browser15 = "Sputnik\\Sputnik\\User Data" wide
        $browser16 = "BraveSoftware\\Brave-Browser\\User Data" wide
        $browser17 = "Microsoft\\Edge\\User Data" wide
        $browser18 = "\\Comodo\\IceDragon\\" wide
        $browser19 = "\\Mozilla\\Firefox\\" wide
        $browser20 = "\\Waterfox\\" wide
        $browser21 = "Chromium\\User Data" wide
        $browser22 = "Iridium\\User Data" wide
        $browser23 = "Chedot\\User Data" wide
        $browser24 = "\\Mozilla\\icecat\\" wide
        $browser25 = "\\8pecxstudios\\Cyberfox\\" wide
        $browser26 = "\\Moonchild Productions\\Pale Moon\\" wide
        $browser27 = "\\Postbox\\" wide
        $browser28 = "Opera Browser" wide
        $browser29 = "Opera Software\\Opera Stable" wide
        $browser30 = "Amigo\\User Data" wide
        $browser31 = "\\Flock\\Browser\\" wide
        $browser32 = "MapleStudio\\ChromePlus\\User Data" wide
        $browser33 = "Comodo\\Dragon\\User Data" wide
        $browser34 = "Kometa\\User Data" wide
        $browser35 = "Coowon\\Coowon\\User Data" wide
        $browser36 = "\\NETGATE Technologies\\BlackHawk\\" wide
        $browser37 = "Google\\Chrome\\User Data" wide
        $browser38 = "Vivaldi\\User Data" wide
        $browser39 = "QIP Surf\\User Data" wide
        $browser40 = "Epic Privacy Browser\\User Data" wide
        $browser41 = "Torch\\User Data" wide

    condition:
        27 of ($browser*)
}

private rule SUS_Special_Key_References_Jan24 {
    meta:
        description = "Detects keyboard reference strings observed in AgentTesla in keyboard/clipboard hooking module."
        author = "Matt Green - @mgreen27"
        date = "2024-01-18"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "ebe2a77dab04458defd4d8f7760abda79a507ab0168d68a2930f9d7b1120127e"
        
    strings:
        $x1 = "_keyboardHook"
        $x2 = "_clipboardHook"
        $x3 = "EnableClipboardLogger"
        $x4 = "KeyloggerInterval"

        $key01 = "{Insert}" wide
        $key02 = "{HOME}" wide
        $key03 = "{PageDown}" wide
        $key04 = "{PageUp}" wide

        $key05 = "{ALT+F4}" wide
        $key06 = "{ALT+TAB}" wide
        
        $key07 = "{KEYDOWN}" wide
        $key08 = "{KEYUP}" wide
        $key00 = "{KEYLEFT}" wide
        $key10 = "{KEYRIGHT}" wide

        $key11 = "{CTRL}" wide
        $key12 = "{DEL}" wide
        $key13 = "{ENTER}" wide
        $key14 = "{TAB}" wide
        $key15 = "{Win}" wide
        $key16 = "{ESC}" wide

        $key17 = "{NumLock}" wide
        $key18 = "{CAPSLOCK}" wide
        $key19 = "{BACK}" wide
        $key20 = "{END}" wide

        $key21 = "{F1}" wide
        $key22 = "{F2}" wide
        $key23 = "{F3}" wide
        $key24 = "{F4}" wide
        $key25 = "{F5}" wide
        $key26 = "{F6}" wide
        $key27 = "{F7}" wide
        $key28 = "{F8}" wide
        $key29 = "{F9}" wide
        $key30 = "{F10}" wide
        $key31 = "{F11}" wide
        $key32 = "{F12}" wide

    condition:
        2 of ($x*) and 20 of ($key*)
}

private rule SUS_Application_References_Jan24 {
    meta:
        description = "Detects application reference strings observed in AgentTesla stealer payload."
        author = "Matt Green - @mgreen27"
        date = "2024-01-18"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "ebe2a77dab04458defd4d8f7760abda79a507ab0168d68a2930f9d7b1120127e"
        
    strings:
        $s01 = "\\Mailbird\\Store\\Store.db" wide
        $s02 = "Software\\Qualcomm\\Eudora\\CommandLine\\" wide
        $s03 = "\\.purple\\accounts.xml" wide //Pidgin
        $s04 = "\\Opera Mail\\Opera Mail\\wand.dat" wide
        $s05 = "UCBrowser\\" wide
        $s06 = "NordVPN" wide
        $s07 = "//setting[@name='Username']/value" wide // Nord
        $s08 = "\\FTPGetter\\servers.xml" wide
        $s09 = "\\FileZilla\\recentservers.xml" wide
        $s10 = "\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" wide
        $s11 = "\\cftp\\Ftplist.txt" wide
        $s12 = "\\Program Files (x86)\\FTP Commander\\Ftplist.txt" wide
        $s13 = "Windows Mail App" wide
        $s14 = "COMPlus_legacyCorruptedStateExceptionsPolicy" wide
        $s15 = "Software\\Microsoft\\ActiveSync\\Partners" wide
        $s16 = "\\Pocomail\\accounts.ini" wide
        $s17 = "HKEY_CURRENT_USER\\Software\\Aerofox\\FoxmailPreview" wide	//Foxmail
        $s18 = "HKEY_CURRENT_USER\\Software\\Aerofox\\Foxmail\\V3.1" wide	//Foxmail
        $s19 = "\\Program Files\\Foxmail\\mail" wide	//Foxmail
        $s20 = "\\Program Files (x86)\\Foxmail\\mail" wide	//Foxmail
        $s21 = "\\Accounts\\Account.rec0" wide	//Foxmail
        $s22 = "\\Account.stg" wide	//Foxmail
        $s23 = /Software\\Microsoft\\Office\\\d{2}\.0\\Outlook\\Profiles/ wide 	//outlook
        $s24 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles" wide 	//outlook
        $s25 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676" wide 	//outlook
        $s26 = "IMAP Password" wide 	//outlook
        $s27 = "POP3 Password" wide 	//outlook
        $s28 = "HTTP Password" wide 	//outlook
        $s29 = "SMTP Password" wide 	//outlook
        $s30 = "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions" wide
        $s31 = "Ipswitch\\WS_FTP\\Sites\\ws_ftp.ini" wide
        $s32 = "\\Common Files\\Apple\\Apple Application Support\\plutil.exe" wide
        $s33 = "\\Apple Computer\\Preferences\\keychain.plist" wide
        $s34 = " -convert xml1 -s -o \"" wide
        $s35 = "\\fixed_keychain.xml" wide
        $s36 = "\\Trillian\\users\\global\\accounts.dat" wide
        $s37 = "\\MySQL\\Workbench\\workbench_user_data.dat" wide
        $s38 = "Local Storage\\leveldb" wide 	//Discord
        $s39 = "discordcanary" wide
        $s40 = "discordptb" wide
        $s41 = "SmartFTP\\Client 2.0\\Favorites\\Quick Connect" wide
        $s42 = "\\FTP Navigator\\Ftplist.txt" wide
        $s43 = "\\Private Internet Access\\data" wide
        $s44 = "Software\\DownloadManager\\Passwords\\" wide
        $s45 = "Software\\IncrediMail\\Identities\\" wide
        $s46 = "Tencent\\QQBrowser\\User Data" wide
        $s47 = "\\Default\\EncryptedStorage" wide
        $s48 = "SOFTWARE\\FTPWare\\COREFTP\\Sites" wide
        $s49 = "\\Claws-mail" wide
        $s50 = "\\falkon\\profiles\\" wide
        $s51 = "SOFTWARE\\RealVNC\\WinVNC4" wide
        $s52 = "Software\\TightVNC\\Server" wide
        $s53 = "Software\\TigerVNC\\Server" wide
        $s54 = "Software\\TightVNC\\Server" wide
        $s55 = "SOFTWARE\\RealVNC\\vncserver" wide
        $s56 = "SOFTWARE\\Wow6432Node\\RealVNC\\WinVNC4" wide
        $s57 = "Software\\ORL\\WinVNC3" wide
        $s58 = "\\uvnc bvba\\UltraVNC\\ultravnc.ini" wide
        $s59 = "Dyn\\Updater\\config.dyndns" wide
        $s60 = "https://account.dyn.com/" wide fullword
        $s61 = "Dyn\\Updater\\daemon.cfg" wide
        $s62 = "Software\\A.V.M.\\Paltalk NG\\common_settings\\core\\users\\creds\\" wide
        $s63 = "\\Microsoft\\Credentials\\" wide
        $s64 = "\\Microsoft\\Protect\\" wide
        $s65 = "\\The Bat!" wide
        $s66 = "\\Account.CFN" wide
        $s67 = "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=" wide
        $s68 = "\\Psi+\\profiles" wide 
        $s69 = "Becky!" wide
        $s70 = "HKEY_CURRENT_USER\\Software\\RimArts\\B2\\Settings" wide
        $s71 = "\\Flock\\Browser\\" wide
        $s72 = "\\Default\\Login Data" wide 	//Opera
        $s73 = "JDownloader 2.0\\cfg" wide
        $s74 = "org.jdownloader.settings.AccountSettings.accounts.ejs" wide	//jdownloader
        $s75 = "jd.controlling.authentication.AuthenticationControllerSettings.list.ejs" wide	//jdownloader

    condition:
         40 of them
}


rule MAL_AgentTesla_Jan24
{
    meta:
        description = "Detects unique strings observed in AgentTesla payload in process memory using private rule references"
        author = "Matt Green - @mgreen27"
        date = "2024-01-18"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "ebe2a77dab04458defd4d8f7760abda79a507ab0168d68a2930f9d7b1120127e"
    strings:
        $dotnet1 = "mscoree.dll" ascii
        $dotnet2 = "mscorlib" ascii
        $dotnet3 = "#Strings" ascii
        $dotnet4 = { 5F 43 6F 72 [3] 4D 61 69 6E }

        $s01 = "https://api.ipify.org" wide fullword	// network
        $s02 = "https://api.telegram.org" wide	// network
        $s03 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0" wide	// network
        $s04 = "multipart/form-data; boundary=" wide	// comms
        $s05 = "Content-Disposition: form-data; name=" wide // comms
        
        $s06 = "Berkelet DB" wide fullword // db access
        $s07 = " 1.85 (Hash, version 2, native byte-order)" wide fullword // Berkelet db access
        $s08 = "SQLite format 3" wide fullword // db access
        
        $s09 = ":Zone.Identifier" wide
        $s10 = "SELECT * FROM Win32_Processor" wide	// local discovery
        $s11 = "Win32_NetworkAdapterConfiguration" wide	// local discovery
        $s12 = "win32_processor" wide	// local discovery
        $s13 = "Win32_BaseBoard" wide	// local discovery

    condition:
        2 of ($dotnet*) and 5 of ($s*) and 
        3 of ( 
                SUS_Exceptions_Jan24, 
                SUS_Windows_Vault_Guids_Jan24, 
                SUS_Browser_References_Jan24, 
                SUS_Special_Key_References_Jan24,
                SUS_Application_References_Jan24
            )
}
