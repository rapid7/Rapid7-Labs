import "pe"

rule goofyloader
{
	meta:
		author = "Tyler McGraw"
		company = "Rapid7"
		date_created = "2024-04-24"
		known_filenames = "python311.dll"
		known_py = "systemd.py"
		known_beacon_types = "sliver"
	strings:
		$b = "Beacon"
		$key = /[0-9a-z]{96}original/
		$dir = "C:\\Users\\Public\\"
		$cpp = "gnu_cxx::"
		$cpp1 = "vector"
		$cpp2 = "append"
		$lset = { ff 15 41 42 0e 00 8b 73 10 48 89 c1 48 89 03 85 f6 7e 0e 41 89 f0 31 d2 49 c1 e0 03 e8 ?? cc 03 00 48 63 d6 b9 40 00 00 00 48 c1 e2 03 ff 15 14 42 0e 00 44 8b 43 10 48 89 c1 45 85 c0 7e 0e 49 c1 e0 03 31 d2 e8 ?? cc 03 00 48 89 c1 }
		$slp_exe = { 48 8b 0e 48 89 ea 48 8b 01 ff 10 48 8b 0e 48 89 ea 48 8b 01 ff 50 08 48 8b 0e 48 89 ea 48 8b 01 ff 50 10 48 8b 2e 48 83 c6 08 48 39 f7 75 d1 }
		$krakenmask = { 41 5b 48 83 c4 08 48 8b 44 24 18 4c 8b 10 4c 89 14 24 4c 8b 50 08 4c 89 58 08 48 89 58 10 48 8d 1d 09 00 00 00 48 89 18 48 89 c3 41 ff e2 }
		$antihook = { 0f b6 01 3c e9 0f 84 e5 00 00 00 3c 90 74 41 3c 8b 75 15 80 79 01 ff 74 77 80 79 05 ff 74 57 31 c0 }
	condition:
    pe.is_pe and pe.characteristics and pe.DLL
			and
		filesize > 10MB
			and
		pe.number_of_signatures == 0 and pe.number_of_exports >= 100
			and
		#b > 10
			and
		all of ($key,$dir)
			and
		any of ($cpp,$cpp1,$cpp2)
			and
		all of ($lset,$slp_exe,$krakenmask,$antihook)
}
