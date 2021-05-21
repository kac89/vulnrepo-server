# VULNRΞPO Server

The server was written in the go language, so make sure do you have it installed. https://golang.org/dl/

## How to start:

1. Clone this repository.
```
git clone https://github.com/kac89/vulnrepo-server.git
```

2. Generate certificate:
```
openssl req -new -x509 -nodes -newkey ec:<(openssl ecparam -name secp384r1) -keyout cert.key -out cert.crt -days 365
```

3. Set your config.json:
```
{
    "Server": {"host":"localhost", "port":"443"},
    "Cert": {"cert":"cert/cert.crt", "certkey":"cert/cert.key"},
    "Auth": {"apikey":"", "User":"Kacper Test", "CREATEDATE": "2021-05-11"},
    "MAX_STORAGE": 1000000000
}
```

4. Set folder permissions (for write) 
```
reports/
```

5. Build binary:
```
go build
```