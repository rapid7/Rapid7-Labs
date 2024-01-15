rule MAL_QuasarRAT_Jan24 {
    meta:
        description = "Detects active QuasarRAT samples targeting observed namespaces in decompiled code and memory"
        author = "Matt Green - @mgreen27"
        date = "2024-01-15"
        reference = "https://www.bitsight.com/blog/unveiling-socks5systemz-rise-new-proxy-service-privateloader-and-amadey"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "ddb34974223511c96173ac8099a9f7ac85c30773c19257137ade8da83f7d4120"
        hash2 = "cd4237029b627009d33bfcf33c18bb7823625d3ba56632196d239bcc03240b69"
   strings:
        $x1 = "Client.exe" wide ascii
        $x2 = "Quasar.Common" wide ascii
        $x3 = "Quasar.Client" wide ascii

        $namespace1 = "Org.BouncyCastle." wide ascii
        $namespace2 = "Gma.System.MouseKeyHook" wide ascii
        $namespace3 = "ProtoBuf.Serializers."

    condition:
      1 of ($x*) and all of ($namespace*)
}