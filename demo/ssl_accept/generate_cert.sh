#!/bin/bash

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=CC/ST=STSTST/L=LLLL/O=Organisation/OU=/CN=admin@essl.fr"
