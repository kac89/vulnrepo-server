# VULNRΞPO Server

*Please note that this is just example how to integrate with [VULNRΞPO](https://github.com/kac89/vulnrepo). The server is intended for personal use!*

API Reference: https://github.com/kac89/vulnrepo/blob/master/API-INTEGRATION.md

The server was written in the go language, so make sure do you have it installed. https://golang.org/dl/

## How to start:

1. Clone this repository.
```
$ git clone https://github.com/kac89/vulnrepo-server.git
```

2. Generate certificate (output put to /cert/ folder):
```
$ openssl req -new -x509 -nodes -newkey ec:<(openssl ecparam -name secp384r1) -keyout cert.key -out cert.crt -days 365
```
Add certificate to your OS browser trusted store to avoid connection problems like: '* remote error: tls: bad certificate*'

3. Set your config.json (set your apikey i propose to use 'uuid v4' or 'uuid v5'):
```
{
    "Server": {"host":"localhost", "port":"443"},
    "Cert": {"cert":"cert/cert.crt", "certkey":"cert/cert.key"},
    "Auth": {"apikey":"", "User":"Kacper Test", "CREATEDATE": "2021-05-11"},
    "MAX_STORAGE": 1000000000,
    "DOWNLOAD_VULNREPOAPP": false
}
```
MAX_STORAGE: 1000000000 bytes = 1 gigabyte.

DOWNLOAD_VULNREPOAPP if set true, the vulnrepo application will be downloaded and launched locally on the server.

4. Set folder permissions (for write) 
```
reports/
```

5. Build binary:
```
$ go build
```

6. RUN:
```
$ ./vulnrepo-server
```
