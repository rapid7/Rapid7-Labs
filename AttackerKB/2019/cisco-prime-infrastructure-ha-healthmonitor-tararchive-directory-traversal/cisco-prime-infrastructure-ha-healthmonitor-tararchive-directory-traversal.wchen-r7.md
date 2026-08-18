---
title: Cisco Prime Infrastructure HA HealthMonitor TarArchive Directory Traversal Remote Code Execution
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2019-05-16T01:29:00'
created: '2019-09-12T18:06:52.838424'
revision_date: '2020-02-13T17:12:23.787668'
assessment_id: 62a14cc1-82ec-4b71-908b-9520a249c5fd
topic_id: bfc08c3d-ed2c-462a-9081-2e5df6fb6415
topic_short_id: QAYiS52Z91
topic_slug: cisco-prime-infrastructure-ha-healthmonitor-tararchive-directory-traversal-remote-code-execution
akb_topic_url: https://attackerkb.com/topics/QAYiS52Z91/cisco-prime-infrastructure-ha-healthmonitor-tararchive-directory-traversal-remote-code-execution
akb_assessment_url: https://attackerkb.com/topics/QAYiS52Z91/cisco-prime-infrastructure-ha-healthmonitor-tararchive-directory-traversal-remote-code-execution#62a14cc1-82ec-4b71-908b-9520a249c5fd
---

# Cisco Prime Infrastructure HA HealthMonitor TarArchive Directory Traversal Remote Code Execution

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/QAYiS52Z91/cisco-prime-infrastructure-ha-healthmonitor-tararchive-directory-traversal-remote-code-execution#62a14cc1-82ec-4b71-908b-9520a249c5fd).*

---

## Description

Cisco Prime Infrastructure (CPI) is a wired and wireless network management software suite that consists of different networking applications from Cisco Systems. The system is used across various industries, from healthcare, manufacturing, government, IT, etc.

A vulnerability was found in the HealthMonitor component, specifically the TarArchive class that is used to extract a Tar file. An unauthenticated user can upload a Tar file that embeds a malicious JSP payload, with a path that traverses back to the web directory. After extraction, the user can send a GET request to trigger the JSP payload, and gain arbitrary remote code execution.

It was originally discovered by Steven Seeley (mr_me) of Source Incite. A detailed write-up is also available [here](https://srcincite.io/blog/2019/05/17/panic-at-the-cisco-unauthenticated-rce-in-prime-infrastructure.html).

## Vulnerable Setup

To trigger this vulnerability, you will need a primary and a secondary server (from the same ISO). Both images require the same hardware setup:

* 4 CPU cores.
* 12288 MB of RAM (12 GB).
* 350GB of space.
* Both VMs should be on the same network.

Make sure the primary server is installed first. To actually recreate the specific vulnerable environment the exploit needs, you will need to install the PI_3_4_1-1.0.27.ubf patch (56a2acbcf31ad7c238241f701897fcb1). Also, create an authentication key, which is completely arbitrary, just like a password. And finally, check with iptables and make sure port 80 isn't blocked if that's the case:

The next VM is the secondary server. The installation is almost the same way, except that you just need to remember to choose you're installing it as a secondary. The setup wizard will ask you the authentication key, and the rest is easy.

For the final step, go to the primary server's administration page, and establish the HA connection to the secondary server.

## Vulnerability Details

Our vulnerability started off with a public report from Source Incite ([SRC-2019-0034](https://srcincite.io/advisories/src-2019-0034/)), which provides the important details about the issue:

> The specific flaw exists within the TarArchive class. The issue results from the lack of proper validation of a user-supplied path prior to using it in file operations. A (remote) attacker can leverage this vulnerability to execute code under the context of root.

After obtaining the vulnerable software and setting it up (thanks to Steven), and SSH into the machine, we start looking for our first clue: the **TarArchive** class.

After browsing around the file system, it looks like most of the CPI code can be found in the `/opt/CSCOlumos/` directory. That is where we want to begin.

### Starting Point: Tar Extraction

At first glance, it isn't very clear how or where the TarArchive class is used, so our first attempt is do a grep for TarArchive, and these results come up:

```
$ grep -R TarArchive *
Binary file compliance/lib/commons-compress-1.8.jar matches
Binary file compliance/lib/IAClasses.zip matches
Binary file lib/pf_third_party/com.cisco.xmp.osgi.tar-2.5.jar matches
Binary file lib/xmp-third-party/xdi-2.0.0.jar matches
Binary file lib/ifm_third_party/commons-compress-1.9.jar matches
Binary file staging/pf/com.cisco.xmp.osgi.tar-2.5.jar matches
Binary file staging/ifm/commons-compress-1.9.jar matches
Binary file staging/ifm/compliance-11-zip.zip matches
```

By going through a few of these with some guesses using a Java decompiler, we found the actual file that contains TarArchive.class:

```
/opt/CSCOlumos/lib/pf_third_party/com.cisco.xmp.osgi.tar-2.5.jar
```

As the path implies, TarArchive is really just a third party library, so we also need to learn which Cisco component is using it. This isn't difficult to figure out. In java, in order to use a library, you must import it first. Back in the jar file, we know that the TarArchive class is in the `com.ice.tar` package, so again, let's grep for that:

```
$ grep -iR "ice.tar" *
Binary file pf/rfm-3.4.0.0.348.jar matches
Binary file pf_third_party/com.cisco.xmp.osgi.tar-2.5.jar matches
Binary file xmp-third-party/xdi-2.0.0.jar matches
```

Going through these files, the **rfm-3.4.0.0.348.jar** seems to be an ideal choice, because there is another class called FileArchiver, which uses the TarArchive.

The FileArchiver class has a method called **extractArchive**, this definitely stands out because our vulnerability is about unsafely extracting a Tar. This isn't a big method, and it doesn't take too long to realize that there are only two important lines of code:

```java
if (destDir != null) {
  try {
    setupReadArchive(istream);
    this.archive.extractContents(destDir);
    result = true;
  }
  ...
```

So let's take a look at setupReadArchive first. It looks like the most important purpose of this method is really to load our Tar file as an InputStream, and load it with TarArchive in `this.archive`:

```java
private boolean setupReadArchive(InputStream istream) throws IOException {
  if (this.archiveName != null && istream == null) {
    try {
      this.inStream = new FileInputStream(this.archiveName);
    }
    catch (IOException ex) {

      this.inStream = null;
      return false;
    } 
  } else {

    this.inStream = istream;
  }  if (this.inStream != null) {
    if (this.compressed) {
      try {
        this.inStream = new GZIPInputStream(this.inStream);
      }
      catch (IOException ex) {

        this.inStream = null;
      } 

      if (this.inStream != null) {
        this.archive = new TarArchive(this.inStream, '���');
      }
    } else {
      this.archive = new TarArchive(this.inStream, '���');
    } 
  }
  ...
```

The next task is calling TarArchive's extractContents method, which is really more like a wrapper for the extractEntry method, so we look at that instead:

```java
private void extractEntry(File paramFile, TarEntry paramTarEntry) throws IOException { if (this.verbose && this.progressDisplay != null)
    this.progressDisplay.showTarProgressMessage(paramTarEntry.getName()); 
  String str = paramTarEntry.getName();
  str = str.replace('/', File.separatorChar);
  File file = new File(paramFile, str);
  if (paramTarEntry.isDirectory()) {
    if (!file.exists() && !file.mkdirs())
      throw new IOException("error making directory path '" + file.getPath() + "'"); 
  } else {
    File file1 = new File(file.getParent());
    if (!file1.exists() && !file1.mkdirs())
      throw new IOException("error making directory path '" + file1.getPath() + "'"); 
    if (this.keepOldFiles && file.exists()) {
      if (this.verbose && this.progressDisplay != null)
        this.progressDisplay.showTarProgressMessage("not overwriting " + paramTarEntry.getName()); 
    } else {
      boolean bool = false;
      FileOutputStream fileOutputStream = new FileOutputStream(file);
      if (this.asciiTranslate) {
        MimeType mimeType = null;
        String str1 = null;
        try {
          str1 = FileTypeMap.getDefaultFileTypeMap().getContentType(file);
          mimeType = new MimeType(str1);
          if (mimeType.getPrimaryType().equalsIgnoreCase("text")) {
            bool = true;
          } else if (this.transTyper != null && this.transTyper.isAsciiFile(paramTarEntry.getName())) {
            bool = true;
          } 
        } catch (MimeTypeParseException mimeTypeParseException) {}
        if (this.debug)
          System.err.println("EXTRACT TRANS? '" + bool + "'  ContentType='" + str1 + "'  PrimaryType='" + mimeType.getPrimaryType() + "'"); 
      } 
      PrintWriter printWriter = null;
      if (bool)
        printWriter = new PrintWriter(fileOutputStream); 
      byte[] arrayOfByte = new byte[32768];
      while (true) {
        int i = this.tarIn.read(arrayOfByte);
        if (i == -1)
          break; 
        if (bool) {
          byte b1 = 0;
          for (byte b2 = 0; b2 < i; b2++) {
            if (arrayOfByte[b2] == 10) {
              String str1 = new String(arrayOfByte, b1, b2 - b1);
              printWriter.println(str1);
              b1 = b2 + 1;
            } 
          } 
          continue;
        } 
        fileOutputStream.write(arrayOfByte, 0, i);
      } 
      if (bool) {
        printWriter.close();
      } else {
        fileOutputStream.close();
      } 
    } 
  }  }
```

The code is a bit thick, but there are some important lines to point out. In the beginning, the first argument of the method is actually the destination directory, which is passed to create a new File object, along with a name extracted from the Tar entry:

```java
String str = paramTarEntry.getName();
str = str.replace('/', File.separatorChar);
File file = new File(paramFile, str);
```

Physically, a Tar archive may have multiple entries, each describing a file. So the first line above pretty much says: "give me the name of this entry". Since this goes to the File object, it is actually where the directory traversal bug is, because that name isn't checked.

The File object then is passed to FileOutputStream, all the way to writing it, and closing the handle:

```java
FileOutputStream fileOutputStream = new FileOutputStream(file);
...
PrintWriter printWriter = null;
if (bool)
  printWriter = new PrintWriter(fileOutputStream); 
byte[] arrayOfByte = new byte[32768];
while (true) {
  int i = this.tarIn.read(arrayOfByte);
  if (i == -1)
    break; 
  if (bool) {
    byte b1 = 0;
    for (byte b2 = 0; b2 < i; b2++) {
      if (arrayOfByte[b2] == 10) {
        String str1 = new String(arrayOfByte, b1, b2 - b1);
        printWriter.println(str1);
        b1 = b2 + 1;
      } 
    } 
    continue;
  } 
  fileOutputStream.write(arrayOfByte, 0, i);
}
...
```

At this point, we have proof that TarArchive's extraction feature is unsafe, the next thing we want to find out is how to actually trigger it remotely.

### Attacker's Entry Point: UploadServlet Class

We know that there is a wrapper class called FileArchive that is using TarArchive. The question to ask is: what is using FileArchive? Well, since the FileArchive class has this unique method named **extractArchive**, the educated guess here is that if there's any code using it, they would be calling extractArchive.

Searching around that particular string in the decompiler, four results show up:

* FileArchiver.class
* FileConsumer.class
* FileExtractor.class
* UploadServlet.class

The first candidate obviously can be eliminated because that's where the method comes from. If you're at this point, it is REALLY difficult not to click on the UploadServlet, because anything that says "upload" in a web application is potentially a vulnerability.

Looking at the UploadServlet class, we immediately identity the code that is using the `extractArchive` method:

```java
private boolean processFileUploadStream(FileItemStream item, InputStream istream, String destDir, String archiveOrigin, boolean archiveIsCompressed, String archiveName, long sizeInBytes, String outputDir) throws IOException {
  boolean result = false;
  
  try {
    FileExtractor extractor = new FileExtractor();
    AesLogImpl.getInstance().info(128, new Object[] { "processFileUploadStream: Start extracting archive = " + archiveName + " size= " + sizeInBytes });
    
    extractor.setDebug(this.debugTar);
    
    result = extractor.extractArchive(istream, destDir, archiveOrigin, archiveIsCompressed);
    ...
```

The processFileUploadStream method is private, and called from a doPost method:

```java
public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
  boolean archiveIsCompressed;
  String fileName = null;
  
  long fileSize = 0L;
  
  result = false;
  response.setContentType("text/html");
  String destDir = request.getHeader("Destination-Dir");
  archiveOrigin = request.getHeader("Primary-IP");
  String fileCount = request.getHeader("Filecount");
  fileName = request.getHeader("Filename");
  String sz = request.getHeader("Filesize");
  if (sz != null)
    fileSize = Long.parseLong(sz); 
  String compressed = request.getHeader("Compressed-Archive");
  if (compressed.equals("true")) {
    archiveIsCompressed = true;
  } else {
    archiveIsCompressed = false;
  } 
  AesLogImpl.getInstance().info(128, new Object[] { "Received archive=" + fileName, " size=" + fileSize + " from " + archiveOrigin + " containing " + fileCount + " files to be extracted to: " + destDir });



  
  ServletFileUpload upload = new ServletFileUpload();
  
  upload.setSizeMax(-1L);
  PropertyManager pmanager = PropertyManager.getInstance(archiveOrigin);
  String outDir = pmanager.getOutputDirectory();
  
  File fOutdir = new File(outDir);
  if (!fOutdir.exists()) {
    AesLogImpl.getInstance().info(128, new Object[] { "UploadServlet: Output directory for archives " + outDir + " does not exist. Continuing..." });
  }


  
  String debugset = pmanager.getProperty("DEBUG");
  if (debugset != null && debugset.equals("true")) {
    this.debugTar = true;
    AesLogImpl.getInstance().info(128, new Object[] { "UploadServlet: Debug setting is specified" });
  } 


  
  try {
    FileItemIterator iter = upload.getItemIterator(request);
    while (iter.hasNext()) {
      FileItemStream item = iter.next();
      String name = item.getFieldName();
      InputStream stream = item.openStream();
      if (item.isFormField()) {
        AesLogImpl.getInstance().error(128, new Object[] { "Form field input stream with name " + name + " detected. Abort processing" });
        
        response.sendError(500, "Servlet does not handle FormField uploads.");
        
        return;
      } 
      
      result = processFileUploadStream(item, stream, destDir, archiveOrigin, archiveIsCompressed, fileName, fileSize, outDir);

      
      stream.close();
    }
  
  } catch (Exception e) {
    AesLogImpl.getInstance().error(128, new Object[] { "doPost - Caught an Exception while handling fileUpload " + e });
  
  }
  catch (OutOfMemoryError e) {
    AesLogImpl.getInstance().error(128, new Object[] { "doPost - Caught an OutOfMemoryError while handling fileUpload " });
  
  }
  catch (Throwable e) {
    AesLogImpl.getInstance().error(128, new Object[] { "doPost - Caught a Throwable while handling fileUpload " + e });
  }
  finally {
    
    if (result) {
      response.setStatus(200);
    } else {
      
      response.sendError(500, "Could not extract archive file from source " + archiveOrigin);
      
      AesLogImpl.getInstance().error1(128, "doPost - could not extract file from source ");
    } 
  } 
}
```

For an HTTP client such as Metasploit's HttpClient mixin, we can send a POST request like this to satisfy the conditions needed for the `doPost` method:

```ruby
post_data = Rex::MIME::Message.new
post_data.add_part(tar.data, nil, nil, "form-data; name=\"files\"; filename=\"#{tar.tar_name}\"")

res = send_request_cgi({
  'method' => 'POST',
  'uri'    => normalize_uri(target_uri.path, 'servlet', 'UploadServlet'),
  'data'   => post_data.to_s,
  'ctype'  => "multipart/form-data; boundary=#{post_data.bound}",
  'headers' =>
    {
      'Destination-Dir' => 'tftpRoot',
      'Compressed-Archive' => 'false',
      'Primary-IP' => '127.0.0.1',
      'Filecount' => '1',
      'Filename' => tar.tar_name,
      'FileSize' => tar.length
    }
})
```

At this point, it is clear to us that we can send a malicious Tar file via a POST request to the UploadServlet (without any authentication), and then that will get extracted by the TarArchive library, allowing us to save the payload outside the intended directory, and gain remote code execution.

### Root Access?

It is worth pointing out that in the public advisory and proof-of-concept, the vulnerability is described to give you remote code execution as root. In reality, you actually only get a lower web privilege for exploiting the TarArchive vulnerability. However, in the /opt/CSCOlumos/bin folder, there is an executable called **runrshell** that actually can be abused to give you root privilege access, and as of now isn't patched by Cisco. This means that as long as you are able to gain remote code execution on Cisco Prime Infrastructure, you should always be get root access by taking advantage of runrshell.

## Credit

Special thanks to Steven Seeley for providing setup, vulnerability information, and other resources in order to produce the Metasploit module.
