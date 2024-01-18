rule MAL_Stealer_Atlantida
{
    meta:
    	author = "Natalie Zargarov @ Rapid7"
        description = "This rule detects the Atlantida info stealer"
        date = "2024-01-17"
        targeting = "Process, Disk"
        tags = "Stealer"
        sample = "b4f4d51431c4e3f7aeb01057dc851454cff4e64d16c05d9da12dfb428715d130"
    strings:
        $trait_0 = {6A 06 68 A4 0D 44 00 C7 85 ?? ?? ?? ?? 01 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 0F 00 00 00 C6 85 ?? ?? ?? ?? 00}
        $trait_1 = {C6 45 ?? 16 8B 95 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 0F 00 00 00 C6 45 ?? 00 83 FA 10}
        $trait_2= {C6 45 ?? 07 8B B5 ?? ?? ?? ?? B8 39 8E E3 38 89 8D ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 2B CE F7 E9 C1 FA 03 8B C2 C1 E8 1F}
    condition:
        2 of ($trait_*)
}