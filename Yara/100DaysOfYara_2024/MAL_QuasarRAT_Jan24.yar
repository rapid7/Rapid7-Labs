rule MAL_QuasarRAT_Jan24 {
    meta:
        description = "Detects active QuasarRAT samples targeting observed namespaces in decompiled code and process memory"
        author = "Matt Green - @mgreen27"
        date = "2024-01-15"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "eb249d8b90aa5fa4627166c0a495f1cdb2a66bf59469a5fb7790a7aad13673fd"
        hash2 = "3ad07a1878c8b77f9fc0143d8f88c240d8d0b986d015d4c0cd881ad9c0d572e"
        
   strings:
        $x1 = "Client.exe" wide fullword
        $x2 = "Quasar.Common" ascii
        $x3 = "Quasar.Client" wide ascii

        $namespace1 = "Org.BouncyCastle." wide ascii
        $namespace2 = "Gma.System.MouseKeyHook" ascii
        $namespace3 = "ProtoBuf.Serializers." ascii

    condition:
      1 of ($x*) and all of ($namespace*)
}