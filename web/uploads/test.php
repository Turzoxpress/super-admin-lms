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
//

rm -v file.jpg

Open the terminal application
To delete everything in a directory run: rm /path/to/dir/*
To remove all sub-directories and files: rm -r /path/to/dir


//----------- For MongoDB backup
chmod -R 777 /www/store

chmod -R 777 ./
sudo docker-compose exec -T db mongodump --quiet --archive --gzip --db SuperAdminDB> dump.gz

sudo docker-compose exec -T db mongorestore --archive --gzip < dump.gz

--------------------------------------

sudo git pull https://github.com/Turzoxpress/super-admin-lms master


-------------------------------------------
sudo su -

--------------------------------------------------------


To show only running containers use the given command:

docker ps

To show all containers use the given command:

docker ps -a

To show the latest created container (includes all states) use the given command:

docker ps -l

To show n last created containers (includes all states) use the given command:

docker ps -n=-1

To display total file sizes use the given command:

docker ps -s

The content presented above is from docker.com.

In the new version of Docker, commands are updated, and some management commands are added:

docker container ls

It is used to list all the running containers.

docker container ls -a

And then, if you want to clean them all,

docker rm $(docker ps -aq)

It is used to list all the containers created irrespective of its state.

And to stop all the Docker containers (force)

docker rm -f $(docker ps -a -q)

Here the container is the management command.


?>