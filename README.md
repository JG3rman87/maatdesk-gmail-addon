# maatdesk-gmail-addon
Pasos para el deploy:
Crear con el gpg(a traves de una maquina de Linux) el fichero encriptado con los tokens a partir del clasp login
gpg -o .clasprc.json.gpg --symmetric --cipher-algo AES256 ./.clasprc.json

y cuando el gpg pida un password, guardarlo como un secret de github


