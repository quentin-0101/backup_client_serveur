``` générer les certificats : 
cd certificats

openssl genpkey -algorithm RSA -out server.key

openssl req -new -key server.key -out server.csr

openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
 
cd ..


sudo apt-get update
sudo apt-get install libsqlite3-dev # sqlite (not use)
sudo apt-get install libpq-dev # postgresql dependency (use)

# compile bcrypt module
cd lib/libbcrypt 
make all

cd ../..
make clean; make all # compile project


Ordre de démarrage : 
build/apikey
une api va être généré
taper l'ip qui sera associé à cette clé api


copier coller cette clé api dans le fichier .api

lancer le serveur
build/server


----- client.conf
REPOSITORY=/home/example1,/home/example2 => répertoires à sauvegarder (récursif) ; il faut séparer les répertoires avec une virgule sans espace
EXTENSION=.test1,.test2 =>  extensions des fichiers à sauvegarder ; il faut séparer les extensions avec une virgule sans espace
SERVER_IP=127.0.0.1 => ip du serveur
SERVER_PORT=1234 => port du serveur
MODE=RESTORE | SYNCHRONIZE      => SYNCHRONIZE permet de lancer une synchronisation sur les nouveau fichiers, et les fichiers modifiés
                                => RESTORE permet de restaurer un fichier au choix, ou tous les fichiers sauvegardés
-------------

lancer le client 
build/client extensions.conf

```
