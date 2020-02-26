
#Generate the openssl configuration files.
PROJECT_NAME="SSL TEST Project"
cat > ca_cert.conf << EOF  
[ req ]
distinguished_name     = req_distinguished_name
prompt                 = no

[ req_distinguished_name ]
 O                      = $PROJECT_NAME Dodgy Certificate Authority
 
EOF

cat > server_cert.conf << EOF  
[ req ]
distinguished_name     = req_distinguished_name
prompt                 = no
 

[ req_distinguished_name ]
 O                      = $PROJECT_NAME
 CN                     = localhost

EOF

cat > client_cert.conf << EOF  
[ req ]
distinguished_name     = req_distinguished_name
prompt                 = no


[ req_distinguished_name ]
 O                      = $PROJECT_NAME Device Certificate
 CN                     = localhost

EOF

mkdir data/ca
mkdir data/server
mkdir data/client
mkdir data/certDER

# private key generation
openssl genrsa -out local_ca.key 1024
openssl genrsa -out local_server.key 1024
openssl genrsa -out local_client.key 1024

# cert requests
openssl req -out local_ca.req -key local_ca.key -new -newkey rsa:2048\
            -config ./ca_cert.conf
openssl req -out local_server.req -key local_server.key -new -newkey rsa:2048\
            -config ./server_cert.conf 
openssl req -out local_client.req -key local_client.key -new -newkey rsa:2048\
            -config ./client_cert.conf 

# generate the actual certs.
openssl x509 -req -in local_ca.req -out local_ca.crt \
            -sha1 -days 5000 -signkey local_ca.key
openssl x509 -req -in local_server.req -out local_server.crt \
            -sha1 -CAcreateserial -days 5000 \
            -CA local_ca.crt -CAkey local_ca.key
openssl x509 -req -in local_client.req -out local_client.crt \
            -sha1 -CAcreateserial -days 5000 \
            -CA local_ca.crt -CAkey local_ca.key

openssl x509 -in local_ca.crt -outform DER -out local_ca.der
openssl x509 -in local_server.crt -outform DER -out local_server.der
openssl x509 -in local_client.crt -outform DER -out local_client.der

mv local_ca.crt local_ca.key data/ca/
mv local_server.crt local_server.key data/server/
mv local_client.crt local_client.key data/client/
# mv local_ca.key data/ca/
mv local_ca.der local_server.der local_client.der data/certDER/

rm *.conf
rm *.req
rm *.srl 


