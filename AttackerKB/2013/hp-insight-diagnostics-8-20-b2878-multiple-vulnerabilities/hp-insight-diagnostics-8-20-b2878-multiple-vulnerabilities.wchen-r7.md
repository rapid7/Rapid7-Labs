---
title: HP Insight Diagnostics 8.20 b2878 multiple vulnerabilities
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2013-06-14T13:07:00'
created: '2019-09-12T18:07:39.607129'
revision_date: '2020-02-13T17:12:12.658057'
assessment_id: 28caa35c-7c72-4dd7-92fc-00149d56422a
topic_id: 4e29add3-1974-4e00-9ced-fc5da3e7c923
topic_short_id: D4hvDc1A1X
topic_slug: hp-insight-diagnostics-8-20-b2878-multiple-vulnerabilities
akb_topic_url: https://attackerkb.com/topics/D4hvDc1A1X/hp-insight-diagnostics-8-20-b2878-multiple-vulnerabilities
akb_assessment_url: https://attackerkb.com/topics/D4hvDc1A1X/hp-insight-diagnostics-8-20-b2878-multiple-vulnerabilities#28caa35c-7c72-4dd7-92fc-00149d56422a
---

# HP Insight Diagnostics 8.20 b2878 multiple vulnerabilities

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/D4hvDc1A1X/hp-insight-diagnostics-8-20-b2878-multiple-vulnerabilities#28caa35c-7c72-4dd7-92fc-00149d56422a).*

---

# Environment:

Tested on both windows and linux (x32) platforms.

The installation requires HP Insight Diagnostics Online Edition & HP System
Management Homepage for Windows or Linux

Used HP System Management Homepage 7.2.0.14 and several versions of HP Insight
Diagnostics Online Edition from 9.1.0.4458 until 9.4.0-562. (Also tested from
branch 8).

# VMWare

Unfortunately is not possible to execute HP Insight Diagnostics by default,
because it isn't a supported manufacturer. The insight solution uses the
encrypted supportesystems.dat in order to have a list os fupported
manufacturers. A Decryptor class in Ruby has been programmed in order to decrypt
the orignal supportesystems.dat, after it a custom Manufacturer (VMWare) can be
added in order to execute HP Insight under VMware, then the file should be
encrypted again (The Decryptor class also allow to encrypt)

# Access to the vulnerable components:

Access to the HP System Management Homepage should be granted in order to use
the vulnerable webapp installed with HP Insight. Anonymous access can be
configured for HP System Management Homepage, which would make this vuln
specially interesting.

# Vulnerable components:

Both components hpdiags/frontend2/commands/saveCompareConfig.php and
hpdiags/frontend2/help/pageview.php are available after installation.

# Vulnerabilities analysis:

CVE-2013-3575 has been found in code as expected, allowing for a restricted PHP
local file inclusion:

```
if (strpos($_GET['path'], '..') !== false ||
    strpos($_GET['path'], '.htm') === false)
  exit('Invalid Path');
// append path to the help directory to ensure we are in the right spot
$path = realpath(dirname(__FILE__) . '/' . $_GET['path']);
```

Later:

```
if (!isset($_GET['word']))
{
  include_once $path;
}
```

But CVE-2013-3574 has not been found. Indeed the exploit vector published at the
original advisory:

```
https://<host>:2381/hpdiags/frontend2/commands/saveCompareConfig.php?filename=comparesurvey&target=winhardrive&device=&devicePath=C:/hp/hpsmh/data/htdocs/hpdiags/frontend2/help/&category=all&advanced=yes&leftFile=surveybase.xml&leftFileName=<%3f=shell_exec($_REQUEST[0])%3b%3f>&rightFile=survey.lastwebsession.xml&rightFileName=-&changesOnly=yes&overwrite=yes
```

Is only available through a (*guessing* old) and unused (commented) FileSaver
class (hpdiags/frontend2/includes/filesaver.class.php):

```
/* <== Commented!
class FileSaver
{
  function doesFileExist($filename, $extension, $target, $mount, $device)
  {
    if ($target == 'winfloppy')
      $mount = 'a:/';
    else if ($mount{strlen($mount)-1} != '/')
      $mount .= '/';
    $filename .= ('.' . $extension);
    $filepath = ($mount . $filename);
    if ($target != 'winfloppy' &&
        $target != 'winhardrive' &&
        $target != 'hardrive')
    {
      $unmountDirectory = true;
(cut)
```

But by using the new FileSaver class the exploit vector commented above isn't available anymore. Even when still is possible save an array to a file:

```
  function saveArrayToFile($filename, $extension, $devicePath, $array)
  {
    $filename = sprintf("%s.%s", $filename, $extension);
    $tempFileName = sprintf("%s.temp_%s", $filename, $extension, date("YmdHis"));
    $tempFilePath = FileSaver::saveArrayToTempDirectory($tempFileName, $array);
    $stdout = AIBridge::copyFileToSaveDevice($tempFilePath, $devicePath, $filename);

    $xml = new XMLDocument($stdout);
    if ($xml)
    {
      $document = $xml->document_element();
      if ($document->tagname() == 'error')
      {
        FileSaver::log($document->get_content());
        @ unlink($tempFilePath);
        return false;
      }
      else if ($document->tagname() != "success")
      {
        FileSaver::log($stdout);
        @ unlink($tempFilePath);
        return false;
      }
    }
    else
    {
      FileSaver::log("Invalid XML: $stdout");
      @ unlink($tempFilePath);
      return false;
    }
    @ unlink($tempFilePath);
    return true;
  }
```


 ButinthisimplementationtheAIBridgeclassisusedtocopythefiletoasavedevice:

```
$stdout = AIBridge::copyFileToSaveDevice($tempFilePath, $devicePath, $filename);
```

The AIBridge class is a way of passing commands to the hpdiagsai.exe (or
hpdiagsai) binary.

In order to make a copyFileToSaveDevice a copyFileToRemovableMediaDevice command
is issued. Unfortunately, the command isn't available on windows:

```
[!] Command
<?xml version="1.0" encoding="UTF-8"?>
<copyFileToRemovableMediaDevice srcPath="C:/hp/hpsmh/session/php/comparesurvey.html.temp_html" devicePath="C:/hp/hpsmh/data/htdocs/hpdiags/frontend2/help/" filename="comparesurvey.html"/>
```

[!] Response

```
<error>../../src/common/diagprocessmain.cpp(line 523), Invalid command</error>
```

And in linux a removable device should be provided:

2013-01-24 00:47:20
aicommand: IN:

```
<?xml version="1.0" encoding="UTF-8"?>
<copyFileToRemovableMediaDevice srcPath="/opt/hp/hpsmh/session/php/comparesurvey.html.temp_html" devicePath="/opt/hp/hpsmh/data/htdocs/hpdiags/frontend2/help/" filename="comparesurvey.html"/>

2013-01-24 00:47:20
aicommand: OUD:
<error>mount failed: source is not a block device (and a device was required).</error>
```
