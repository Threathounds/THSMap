#!/bin/bash

pip3 install curl wget git wkhtmltopdf libssl1.0-dev vim nmap tzdata
wget https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/wkhtmltox-0.12.4_linux-generic-amd64.tar.xz
tar -xvf wkhtmltox-0.12.4_linux-generic-amd64.tar.xz

mkdir notes
mkdir xml

python3 manage.py migrate
echo "Your token is $(python3 thsdashboard/token.py | cut -f 2 -d ' ')"
