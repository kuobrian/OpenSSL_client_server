
# Use OpenSSL client certificate

+ CA certificate
+ server and client (using Flask package)

## Create CA certificate
```

# Create a CA (Certificate Authority) [local_ca.ctr]
# Generate Server Certificates        [local_server.key, local_server.crt]
# Generate Client Certificates        [local_client.key, local_client.crt]

bash data/makecert.sh
```
cnf file:
1. CN (Common Name)是憑證名稱，你可以設定任意名稱，設定中文也可以，要以 UTF-8 編碼存檔

## Local Server

```
python server.py
```




# Certificates Generation

openssl req -nodes -new -x509 -days 365 -keyout ca.key -out ca-crt.pem

# Generate Server Certificates

- generate a private key
- create a CSR (Certificate Signing Request) which is basically a statement file with - details about the server that wants to obtain a certificate
- try to issue the certificate for the server based on its CSR through CA. The generated certificate will contain details about the server (from CSR), its public key and CA’s - digital signature that is used by the clients to verify the trustworthiness of - - certificate.
- Note that for CSR, you will be required to enter details about the server, therefore make sure to specify them accordingly.

```

# create server private key and server CSR

openssl req -nodes -new -keyout server.key -out server.csr -config 

# generate certicate based on server's CSR using CA root certificate and CA private key

openssl x509 -req -days 365 -in server.csr -CA ca-crt.pem -CAkey ca.key -CAcreateserial -out server.crt -config 

# verify the certificate (optionally)
openssl verify -CAfile ca-crt.pem server.crt

```

# Generate Client Certificates
```
# create client private key and client CSR
openssl req -nodes -new -keyout client.key -out client.csr

# generate certicate based on client's CSR using CA root certificate and CA private key
openssl x509 -req -days 365 -in client.csr -CA ca-crt.pem -CAkey ca.key -CAcreateserial -out client.crt

# verify the certificate (optionally)
openssl verify -CAfile ca-crt.pem client.crt

```

# 透過以下命令就可以建立出 私密金鑰 (server.key) 與 憑證檔案 (server.crt)：

openssl req -x509 -new -nodes -sha256 -utf8 -days 3650 -newkey rsa:2048 -keyout server.key -out server.crt -config .\ssl.conf