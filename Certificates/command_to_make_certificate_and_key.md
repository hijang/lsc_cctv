# Self-signed server key and certificate

## Root CA
### Root CA key
> openssl ecparam -out rootca.key -name prime256v1 -genkey

### CSR(Certificae Signiture Request) for Root Certificate
> openssl req -new -sha256 -key rootca.key -out rootca.csr

### Make Root CA and self-sign
> openssl x509 -req -sha256 -days 999999 -in rootca.csr -signkey rootca.key -out rootca.crt

## Server key
### Make private key for server
> openssl ecparam -out server.key -name prime256v1 -genkey

### CSR(Certificae Signiture Request) for server
> openssl req -new -sha256 -key server.key -out server.csr

### Make certificate for server and sign it.
> openssl x509 -req -sha256 -days 999999 -in server.csr -CA rootca.crt -CAkey rootca.key -CAcreateserial -out server.crt

### Describe server certificate.
> openssl x509 -in server.crt -text -noout

### Make certificate for server
> cat server.crt rootca.crt > server.pem

## Client key
### Make private key for client - RSA 2048키 생성 및 개인키를 AES256으로 암호화
> openssl genrsa -aes256 -passout pass:jeff -out client.pem 2048
```
$ openssl genrsa -des3 -passout pass:jeff -out client.key 2048
Generating RSA private key, 2048 bit long modulus (2 primes)
...............+++++
...................................................+++++
$ openssl req -new -key client.key -out client.csr
Enter pass phrase for client.key:
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:KR
State or Province Name (full name) [Some-State]:Seoul
Locality Name (eg, city) []:Gangnam
Organization Name (eg, company) [Internet Widgits Pty Ltd]:LGE
Organizational Unit Name (eg, section) []:SecSpecialist
Common Name (e.g. server FQDN or YOUR name) []:4tential host PC
Email Address []:tehloo@gmail.com

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:

```
### 패스워드 제거
```
➜  Certificates git:(main) ✗ cp client.key client.key.passwd
➜  Certificates git:(main) ✗ openssl rsa -in client.key.passwd -out client.key
Enter pass phrase for client.key.passwd:
writing RSA key
➜  Certificates git:(main) ✗ ll
total 48K
-rw-r--r-- 1 tehloo tehloo 1.1K Jun  6 16:09 client.csr
-rw------- 1 tehloo tehloo 1.7K Jun  6 16:11 client.key
-rw------- 1 tehloo tehloo 1.8K Jun  6 16:10 client.key.passwd
```
### 인증서 생성
```
➜  Certificates git:(main) ✗ openssl x509 -req -days 365 -in client.csr -CA rootca.crt -CAkey rootca.key -CAcreateserial -out client.crt
Signature ok
subject=C = KR, ST = Seoul, L = Gangnam, O = LGE, OU = SecSpecialist, CN = 4tential host PC, emailAddress = tehloo@gmail.com
Getting CA Private Key
```