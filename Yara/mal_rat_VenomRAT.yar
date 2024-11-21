import "dotnet"

rule mal_rat_VenomRAT {
  meta:
    author = "Rapid7 Labs"
    description = "Detects VenomRAT variant"
    sha = "1574d418de3976fc9a2ba0be7bf734b919927d49bd5e74b57553dfc6eee67371"
    target_entity = "file"
  strings:
    $s1      = "select * from Win32_VideoController" wide
    $s2      = "Select * From Win32_ComputerSystem" wide
    $s3      = "Select * from Win32_Processor" wide
    $s4      = "Select * from AntivirusProduct" wide
    $s5      = "IID_IPropertyBag"

    $dll     = "amsi.dll" base64wide
    $bypass1 = "AmsiScanBuffer" wide ascii nocase
    $bypass2 = "EtwEventWrite" wide ascii nocase

    $il1     = { 72 77 22 00 70 28 ?? ?? ?? ?? 0A }
    $il2     = { 72 91 22 00 70 }
    $il3     = { 7E ?? ?? ?? 04 28 ?? ?? ?? ?? 7E ?? ?? ?? 04 28 ?? ?? ?? ?? 2A }

    $dotnet1 = "mscoree.dll" ascii nocase
    $dotnet2 = "mscorlib" ascii nocase
    $dotnet3 = "System.Windows.Forms" ascii nocase
    $dotnet4 = "System.IO" ascii nocase

  condition:
    all of them and
    dotnet.number_of_streams > 0 and
    dotnet.streams[3].name == "#GUID" and dotnet.streams[3].size == 16 and
    dotnet.streams[2].name == "#US" and dotnet.streams[2].size == 9312 and
    dotnet.streams[4].name == "#Blob" and dotnet.streams[4].size == 5548 and
    dotnet.module_name == "Client.exe" and dotnet.is_dotnet
}
