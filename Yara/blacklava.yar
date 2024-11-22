import "pe"

rule blacklava {
	meta:
		author = "Tyler McGraw"
		company = "Rapid7"
		created = "2024-07-28"
		why = "This rule detects a packer used by Black Basta ransomware operators to load malware."
	strings:
		//$d1 = { ac [0-8] e9 }
		$d2 = { 02 c3 [0-8] e9 }
		$d3 = { 32 c3 [0-8] e9 }
		$d4 = { 2a c3 [0-8] e9 }
		$d5 = { c0 c0 ?? [0-8] e9 }
		//$d6 = { aa [0-8] e9 }
		//$d7 = { 49 [0-8] e9 }
		$dc1 = { 8a 06 ( 46 | ?? ) [0-8] e9 }
		//$dc2a = { 3c 20 [0-8] ( 0f 8? | e9 ) }
		$dc2b = { 3c 40 [0-8] ( 0f 8? | e9 ) }
		$dc3a = { 87 d6 [0-8] e9 }
		$dc3b = { 87 f2 [0-8] e9 }
		//$dc4 = { 91 [0-8] e9 }
		$dc5 = { f3 a4 [0-8] e9 }
		$dc6 = { 8d 57 ff [0-8] e9 }
		$dc7 = { 8d 48 20 [0-8] e9 }
		$dc8 = { 8d 49 03 [0-8] e9 }
		$dc9 = { c1 e0 ( 05 | 06 ) [0-8] e9 }
		$dc10 = { c1 eb 06 [0-8] e9 }
		$dc11 = { 81 c1 ff 00 00 00 [0-8] e9 }
		$dc12 = { b9 18 01 00 00 [0-8] e9 }
		$e1 = { 8b ff e9 [4] ~cc }
		$e2 = { 83 c4 ec [0-8] e9 }
		$e3 = { c7 45 ee 00 00 00 00 [0-16] e9 }
		$e4 = { c7 45 f2 01 00 00 00 [0-16] e9 }
		$e5 = { c7 45 f6 00 00 00 00 [0-16] e9 }
		$e6 = { c7 45 fa ?? ?? ?? ?? [0-16] e9 }
		$e7 = { 81 c4 9c fc ff ff [0-8] e9 }
		$p1 = { e9 00 00 00 00 }
	condition:
                pe.is_pe and pe.is_32bit()
			and
		for any i in (0..pe.number_of_sections-1) : ( 
			pe.sections[i].name == ".text" 
			and
			all of ($d*,$dc*,$e*,$p*) in (pe.sections[i].raw_data_offset..pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size)
		)
}
