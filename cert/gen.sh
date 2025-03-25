#!/bin/bash
sudo openssl req -nodes -x509 -newkey rsa:2048 -days 365 -keyout  server.key -out server.crt