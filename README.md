``` générer les certificats : 
cd certificats

openssl genpkey -algorithm RSA -out server.key

openssl req -new -key server.key -out server.csr

openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
 
cd ..

make clean; make all
