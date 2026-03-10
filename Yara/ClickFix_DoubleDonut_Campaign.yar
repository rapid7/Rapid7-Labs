rule clickfix_compromised_website
{
    meta:
        author = "Milan Spinka @ Rapid7 Labs"
        description = "Identifies WordPress websites infected by DoubleDonut ClickFix campaign."

    strings:
        $ = "try { eval(jsCode); } catch(e) { console.error('Cache optimize error', e); }"
        $ = "window.__performance_optimizer_v6=true;"
        $ = "var endpointUrl=atob(perfEndpoints[endpointIndex])+Math.random();"
        $ = "if (window.__AJJS_LOADED__) return;"
        $ = "if (/iframeShown=true/.test(cookies)) return;"
        $ = "if (/wordpress_logged_in_|wp-settings-|wp-saving-|wp-postpass_/.test(cookies)) return;"
        $ = "/wp-admin/admin-ajax.php?action=ajjs_run"

    condition:
        any of them
}

rule clickfix_injector_javascript
{
    meta:
        author = "Milan Spinka @ Rapid7 Labs"
        description = "Identifies ClickFix injection script from the DoubleDonut campaign."
        reference = "https://urlscan.io/responses/8c83b46a7ca674bf717765b734a919c78556c193d1942de94be409c4ed663d1a/"

    strings:
        $ = "TARGET_URL=_0x"
        $ = "let finalUrl;"
        $ = "try{const u=new URL(TARGET_URL)"
        $ = "finalUrl=TARGET_URL+sep+encodeURIComponent("
        $ = "let showIframe="

    condition:
        3 of them
}

rule clickfix_fake_captcha_html
{
    meta:
        author = "Milan Spinka @ Rapid7 Labs"
        description = "Identifies fake CAPTCHA lures from the DoubleDonut ClickFix campaign."
        example_url = "hxxps[://]greecpt[.]shop/captcha.html"

    strings:
        $head1 = "<title>Security Check</title>"
        $head2 = "<link rel=\"stylesheet\" href=\"captcha.css\">"

        $body1 = "<textarea id=\"clipboard-text\" readonly></textarea>"
        $body2 = "<span id=\"verifying-text\">\xE3\x85\xA4</span>"

    condition:
        any of ($head*) and
        any of ($body*)
}

rule donut_loader_shellcode
{
    meta:
        author = "Milan Spinka @ Rapid7 Labs"
        description = "Identifies Donut Loader shellcode (observed in ClickFix campaigns to deliver infostealers)."

    strings:
        $entry_point = {
            59    // pop     ecx
            31 C0 // xor     eax, eax
            48    // dec     eax
            0F    // js      loc_A0BB
        }

    condition:
        uint8(0) == 0xE8 and                        // near, relative call
        int32(1) >= 0 and                           // positive displacement
        uint32(5) > 0 and uint32(5) <= 0xFFFFFF and // payload size
        $entry_point at (uint32(1) + 5)             // signature found at target of call at offset 0
}

import "pe"

rule double_donut_loader_strings
{
    meta:
        author = "Milan Spinka @ Rapid7 Labs"
        description = "Identifies DoubleDonut loader (a.k.a. VodkaStealer loader) used to deliver infostealers in ClickFix campaigns."
        hash = "6437db6158ee8fa2d316ba3625ca8df6afdb9304bb3c1e6ee4fb0bcdabb7f212"

    strings:
        $ = "SeDebugPrivilege\x00"
        $ = "Mozilla/5.0\x00" wide
        $ = "user_profiles_photo" wide
        $ = "svchost.exe\x00" wide

    condition:
        for any section in pe.sections: (
            (section.name == ".rdata" or section.name == ".rodata") and
            (all of them in (section.raw_data_offset .. section.raw_data_offset + 1024))
        )
}

rule vidar_stealer_v2_strings
{
    meta:
        author = "Milan Spinka @ Rapid7"
        description = "Identifies obfuscated Vidar v2 payloads based on static sequences."
        hash = "de5d188dae7206097f4615a07fb0a1c53903936f8d71abe69b494c24af79b27d"

    strings:
        $x01 = "C:\\ProgramData\\\x00" xor
        $x02 = "\\logins.json\x00" xor
        $x03 = "Browser List\x00" xor
        $x04 = "Chromium Plugins\x00" xor
        $x05 = "Firefox Plugins\x00" xor
        $x06 = "Wallet Rules\x00" xor
        $x07 = "File Grabber Rules\x00" xor
        $x08 = "Loader Tasks\x00" xor
        $x09 = "\\IndexedDB\\chrome-extension_\x00" xor
        $x10 = "\\Network\\Cookies\x00" xor
        $x11 = "%DRIVE_FIXED%\x00" xor
        $x12 = "%DRIVE_REMOVABLE%\x00" xor
        $x13 = "Files\\\x00" xor
        $x14 = "chromium_plugins\\Local Extension Settings\\\x00" xor
        $x15 = "\\IndexedDB\\chrome-extension_\x00" xor
        $x16 = "browser_files\x00" xor
        $x17 = "APPDATA\x00" xor
        $x18 = "%LOCALAPPDATA%\x00" xor
        $x19 = "SOFTWARE\\Microsoft\\Cryptography\x00" xor

        $warning_malware = "WARNING: MALWARE!\n\nThe binary should be protected with a packer/crypter\nbefore distribution to avoid detection.\n\n\x00" xor
        $base91 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$&()*+,-./:;<=>?@[]^_`{|}~ \x00"

    condition:
        uint16(0) == 0x5a4d and
        (
            $warning_malware or
            ($base91 and 10 of ($x*))
        )
}

rule impure_stealer_method_names
{
    meta:
        author = "Milan Spinka @ Rapid7 Labs"
        description = "Identifies Impure Stealer payloads by cleartext method names."
        hash = "b73d9535dea3d153abedae031b0f4534d68bf881b72554eeb5a48f4752ee4f7d"

    strings:
        $ = "get_Discords"
        $ = "set_Discords"
        $ = "get_IsChromium"
        $ = "set_IsChromium"
        $ = "get_VideoControllers"
        $ = "set_VideoControllers"
        $ = "get_PotentialBrowsers"
        $ = "set_PotentialBrowsers"
        $ = "get_Wallets"
        $ = "set_Wallets"
        $ = "get_Accounts"
        $ = "set_Accounts"
        $ = "get_LoginDataForAccount"
        $ = "set_LoginDataForAccount"
        $ = "get_AppBoundKey"
        $ = "set_AppBoundKey"

    condition:
        uint16(0) == 0x5a4d and
        all of them
}

rule vodka_stealer_strings
{
    meta:
        author = "Milan Spinka @ Rapid7 Labs"
        description = "Identifies payloads of VodkaStealer by cleartext strings."
        hash = "d8f3ee9dd462c7745db488bc4a8e77ea11b79048ce952b66e55665c530de2ddc"

    strings:
        $m01 = "/user_profiles_photo/chromelevator.bin"
        $m02 = "%s\\chromelevator_output"
        $m03 = "Ip: %s\r\nCountry: %s\r\n\r\nDate: %s\r\nMachineID: %s\r\nGUID: %s\r\nHWID: %s\r\n\r\nPath: %s\r\n\r\nWindows: %s\r\nInstall Date: %s\r\nAV: Windows Defender\r\nComputer Name: %s\r\nUser Name: %s\r\nDisplay Resolution: %s\r\nKeyboard Languages: %s\r\nLocal Time: %s\r\nTimeZone: %d\r\n\r\n[Hardware]\r\nProcessor: %s\r\nCores: %lu\r\nThreads: %lu\r\nRAM: %s\r\nVideoCard: %s\r\n"
        $m04 = "sysinfo_aes256_channel_key_2024!!"
        $m05 = "Global\\sysinfo_single_instance"

        $s01 = "logins.json"
        $s02 = "systeminfo.txt"
        $s03 = "First run: %02d/%02d/%04d %02d:%02d:%02d"
        $s04 = "chromelevator_output"
        $s05 = "%s\\InstalledSoftware.txt"

    condition:
        uint16(0) == 0x4d5a and
        (
            any of ($m*) or
            all of ($s*)
        )
}