rule HKTL_BruteRatel
{
    meta:
        author = "Natalie Zargarov @ Rapid7"
        description = "This rule detects the anti-debugging and anti-hooking techniques of BruteRatel tool along with several NT function hashes"
        target = "process"
    strings:
        $trait_0 = {44 8A 09 41 80 F9 E9 74 ?? 44 8A 41 ?? 41 80 F8 E9}
        $trait_1 = {80 79 ?? 8B 75 ?? 80 79 ?? D1 75 ?? 41 80 F8 B8}
        $trait_2= {65 48 8B 04 25 ?? ?? ?? ?? 48 8B 80 ?? ?? ?? ?? 4C 89 84 24 ?? ?? ?? ?? 83 E0 70 3C 70}
        $hash_0 = {B9 2B 8B 53 9A} //NtCreateSection
        $hash_1 = {B9 A1 60 B0 D3} //NtMapViewOfSection
        $hash_2 = {B9 EC 07 2A CD} //NtQueueApcThread
        $hash_3 = {B9 BD F3 64 F8} //NtGetContextThread
        $hash_4 = {B9 57 E0 B6 AF} //NtSetContextThread
        $hash_5 = {B9 93 C1 65 7A} //NtWriteVirtualMemory
    condition:
        2 of ($trait_*) and 
        3 of ($hash_*)
}
