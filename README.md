``` générer les certificats : 
cd certificats

openssl genpkey -algorithm RSA -out server.key

openssl req -new -key server.key -out server.csr

openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
 
cd ..


sudo apt-get update
sudo apt-get install libsqlite3-dev

make clean; make all

build/apikey
une api va être généré
taper l'ip qui sera associé à cette clé api


copier coller cette clé api dans le fichier .api

lancer le serveur
build/server

lancer le client 
build/client IP PORT SYNCHRONIZE|RESTORE path-to-save extensions.conf

```

postgresql compile macos : gcc postgresql.c -o postgresql -I/opt/homebrew/opt/libpq/include -L/opt/homebrew/opt/libpq/lib -lpq