rule WebWorm_NtMonitor_strings
{
	meta:
		author = "Milan Spinka @ Rapid7 Intelligence"
		description = "Identifies customized 'NtMonitor' repacks of SoftEther VPN bridge by plaintext strings."

	strings:
		// $ = "NtMonitor"
		$ = "@setting.conf\x00"
		$ = "/update/picture.cgi\x00"
		$ = "/update/alive.cgi\x00"

	condition:
		uint16(0) == 0x5a4d
		and all of them
}

rule WebWorm_NtMonitor_PDB
{
	meta:
		author = "Milan Spinka @ Rapid7 Intelligence"
		description = "Identifies customized 'NtMonitor' repacks of SoftEther VPN bridge by PDB path."

	strings:
		$ = "C:\\Users\\Administrator\\Desktop\\SoftEtherVPN_Stable\\SoftEtherVPN_Stable\\SoftEtherVPN_Stable\\src\\DebugFiles\\pdb\\x64_Release\\vpnbridge.pdb"

	condition:
		uint16(0) == 0x5a4d
		and all of them
}

rule WebWorm_NtMonitor_encrypted_config
{
	meta:
		author = "Milan Spinka @ Rapid7 Intelligence"
		description = "Identifies encrypted SoftEther VPN bridge configuration files used by the 'NtMonitor' repack."

	strings:
		$magic_and_key = /RCEN\x10\x00\x00\x00[ -~]{16}/

	condition:
		$magic_and_key at 0
}
