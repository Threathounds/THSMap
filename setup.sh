#!/bin/bash

apt install xfonts-75dpi
# pip3 install curl wget git wkhtmltopdf libssl1.0-dev vim nmap tzdata
wget https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.5/wkhtmltox_0.12.5-1.stretch_amd64.deb
dpkg -i wkhtmltox-0.12.5-1.stretch_amd64.deb

mkdir notes
mkdir xml

python3 manage.py migrate
sleep 1
echo "Use this token: $(python3 thsdashboard/token.py | cut -f 2 -d ' ')"
sleep 1
python3 manage.py runserver
