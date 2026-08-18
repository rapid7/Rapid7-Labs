---
title: Samsung SRN-1670D Web Viewer Version 1.0.0.193 Arbitrary File Read and Upload
author: jvazquez-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2017-11-06T08:29:00'
created: '2019-09-12T18:07:11.545803'
revision_date: '2020-02-13T17:12:19.523202'
assessment_id: 57d03c8f-8fc0-4295-a4f5-4e330ee2cc23
topic_id: e3d19c07-c95a-439c-90bd-63f8777c6ec0
topic_short_id: CP18z8x3Nv
topic_slug: samsung-srn-1670d-web-viewer-version-1-0-0-193-arbitrary-file-read-and-upload
akb_topic_url: https://attackerkb.com/topics/CP18z8x3Nv/samsung-srn-1670d-web-viewer-version-1-0-0-193-arbitrary-file-read-and-upload
akb_assessment_url: https://attackerkb.com/topics/CP18z8x3Nv/samsung-srn-1670d-web-viewer-version-1-0-0-193-arbitrary-file-read-and-upload#57d03c8f-8fc0-4295-a4f5-4e330ee2cc23
---

# Samsung SRN-1670D Web Viewer Version 1.0.0.193 Arbitrary File Read and Upload

*Assessment by jvazquez-r7, archived from [AttackerKB](https://attackerkb.com/topics/CP18z8x3Nv/samsung-srn-1670d-web-viewer-version-1-0-0-193-arbitrary-file-read-and-upload#57d03c8f-8fc0-4295-a4f5-4e330ee2cc23).*

---

## Details

The vulnerable code can be found in network_ssl_upload.php:

```php
    22 $path = "./upload/";
    23 $file = $_FILES[ "attachFile" ];
    24 $isApply = ( int )$_POST[ "is_apply" ];
    25 $isInstall = ( int )$_POST[ "isInstall" ];
    26 $isCertFlag = ( int )$_POST[ "isCertFlag" ];
    27
    28 // create socket
    29 $N_message = "";
    30 $sock = mySocket_create($_is_unix_socket);
    31 $connected = mySocket_connect($_is_unix_socket, $sock);
    32
    33 $loginInfo = new loginInfo();
    34 $retLogin = loginManager( $connected, $sock, null, $loginInfo );
    35 if ( ( $retLogin == true ) && ( $isApply == 2 || $isApply == 3 ) ) {
    36  if ($connected) {
    37   $id = $loginInfo->get_id();
    38   $xmlFile = $id.'_config.xml';
    39   $N_message = "dummy".nvr_command::DELIM;
    40   $N_message .= "userid ".$id.nvr_command::DELIM;
    41
    42   if ( $isInstall == 1 ) {
    43    // File upload ===============================================================
    44    if ( $file[ "error" ] 0 ) {
    45     $Error = "Error: ".$file[ "error" ];
    46    } else {
    47     $retFile = @copy( $file[ "tmp_name" ], $path.$file[ "name" ] );
    48    }
    49    // ===========================================================================
    50   }
```

To avoid the need of authentication, the exploit also takes advantage of another vulnerability
(CVE-2015-8279) in the log exporting function to read an arbitrary file from the remote machine
in order to obtain credentials that can be used for the attack.
