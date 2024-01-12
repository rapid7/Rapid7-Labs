rule MAL_Socks5Systemz_Jan24 {
    meta:
        description = "Detects active Socks5Systemz samples targeting unique strings (connection and install timestamp) using Velociraptor"
        author = "Matt Green - @mgreen27"
        date = "2024-01-12"
        reference = "https://www.bitsight.com/blog/unveiling-socks5systemz-rise-new-proxy-service-privateloader-and-amadey"
        artifact = "Windows.Detection.Yara.Process"
        hash1 = "ddb34974223511c96173ac8099a9f7ac85c30773c19257137ade8da83f7d4120"
        hash2 = "cd4237029b627009d33bfcf33c18bb7823625d3ba56632196d239bcc03240b69"
   strings:
        $s1 = /http:\/\/.{6,100}\/click\/\?counter=[0-9a-f]{184}/ wide ascii
        $s2 = "client_id=%.8x&connected=%d&server_port=%d&debug=%d&os=%d.%d.%04d&dgt=%d&dti=%d"
        $s3 = /C:\\ProgramData\\ts\d{,2}\.dat/
    condition:
        any of them
}