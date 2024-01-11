rule RussianWordsInPDBPath {
    meta:
        description = "Detects PE files with specific Russian language strings in the PDB path"
        author = "Your Name"
        date = "2024-01-10"

    strings:
        // Hexadecimal representation of "эксплоит" in UTF-16LE
        $exploit = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}(4D 04 3A 04 41 04 3F 04 3B 04 3E 04 38 04 42 04)[\x00-\xFF]{0,200}\.pdb\x00/ wide

        // Hexadecimal representation of "Администратор" in UTF-16LE
        $administrator = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}(10 04 34 04 3C 04 38 04 3D 04 38 04 41 04 42 04 40 04 30 04 42 04 3E 04 40 04)[\x00-\xFF]{0,200}\.pdb\x00/ wide

        // Hexadecimal representation of "Админ" in UTF-16LE
        $admin = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}(10 04 34 04 3C 04 38 04 3D 04)[\x00-\xFF]{0,200}\.pdb\x00/ wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x4550 and
        filesize < 3MB and
        ($exploit or $administrator or $admin)
}

