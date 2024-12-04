import "pe"

rule blacklava
{
	meta:
		author = "Tyler McGraw"
		company = "Rapid7"
		date_created = "2024-07-28"
		version = "2"
		desc = "Detects a packer used by Black Basta ransomware operators to load malware."
	strings:
		$d2 = { 02 c3 [0-8] e9 [3] ( 00 | ff ) }
		$d3 = { 32 c3 [0-8] e9 [3] ( 00 | ff ) }
		$d4 = { 2a c3 [0-8] e9 [3] ( 00 | ff ) }
		$d5 = { c0 c0 ?? [0-8] e9 [3] ( 00 | ff ) }
		$dc1 = { 8a 06 [0-8] e9 [3] ( 00 | ff ) }
		$dc2b = { 3c 40 [0-8] e9 [3] ( 00 | ff ) }
		$dc3a = { 87 d6 [0-8] e9 [3] ( 00 | ff ) }
		$dc3b = { 87 f2 [0-8] e9 [3] ( 00 | ff ) }
		$dc5 = { f3 a4 [0-4] e9 [3] ( 00 | ff ) }
		$dc6 = { 8d 57 ff [0-8] e9 [3] ( 00 | ff ) }
		$dc7 = { 8d 48 20 [0-8] e9 [3] ( 00 | ff ) }
		$dc8 = { 8d 49 03 [0-8] e9 [3] ( 00 | ff ) }
		$dc9 = { c1 e0 ( 05 | 06 ) [0-8] e9 [3] ( 00 | ff ) }
		$dc10 = { c1 eb 06 [0-8] e9 [3] ( 00 | ff ) }
		$dc11 = { 81 c1 ff 00 00 00 [0-8] e9 [3] ( 00 | ff ) }
		$dc12 = { b9 18 01 00 00 [0-8] e9 [3] ( 00 | ff ) }
		$dc13 = { 08 c0 [0-6] e9 [3] ( 00 | ff ) }
		$dc14 = { 0f 84 [4] e9 [3] ( 00 | ff ) }
		$dc15 = { 29 c2 [0-8] e9 [3] ( 00 | ff ) } 
		$dc16 = { c1 e0 05 [0-8] e9 [3] ( 00 | ff ) }
		$oe1a = { 8b ec e9 [3] ( 00 | ff ) ~cc }
		$oe1b = { 8b ff e9 [3] ( 00 | ff ) ~cc }
		$e2 = { 83 c4 e? [0-8] e9 [3] ( 00 | ff ) }
		$e3 = { c7 45 ( f2 | f4 | f6 ) ?? ?? 0? 00 [0-8] e9 [3] ( 00 | ff ) }
		$n = { 8b 45 f4 [0-4] e9 [3] ( 00 | ff ) }
		$p1 = { e9 00 00 00 00 }
		$j = { ( 0f 84 | 0f 85 | 31 c0 | 33 c0 ) [0-8] e9 [1] ( ~0? ?? 00 | ~f? ~ff ff ) }

	condition:
        pe.is_pe and pe.is_32bit()
		and
	for any i in (0..pe.number_of_sections-1) : ( 
		pe.sections[i].name == ".text"
		and
		#dc5 >= 3 and #j >= 10
		and
		($oe1a or $oe1b)
		and
		all of ($d*,$dc*,$e*,$n*,$p*) in (pe.sections[i].raw_data_offset..pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size)
	)
}
