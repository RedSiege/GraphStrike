#!/bin/bash

if [ $(id -u) != "0" ]; then
echo "You must be the superuser to run this script" >&2
exit 1
fi

apt-get update

apt-get -y install nasm
apt-get -y install mingw-w64
apt-get -y install python3-venv
apt-get -y install make