<?php

sudo chmod 666 /var/run/docker.sock

sudo docker stop $(docker ps -a -q)

sudo docker rm $(docker ps -a -q)

//----------

ses-smtp-user.20200824-160411

SMTP Username:
AKIAUWJ6HWYKQOPXBNFT

SMTP Password:
BGY/sFIu1up+j/HvTaCPQQjFRuN3w1v46qpFTroG4j7j

//--------------------------------

Open the terminal application
To delete everything in a directory run: rm /path/to/dir/*
To remove all sub-directories and files: rm -r /path/to/dir


//----------- For MongoDB backup
sudo docker-compose exec -T db mongodump --quiet --archive --gzip --db SuperAdminDB> dump.gz


sudo docker-compose exec -T db mongorestore --archive --gzip < dump.gz

--------------------------------------

sudo git pull https://github.com/Turzoxpress/super-admin-lms master




?>