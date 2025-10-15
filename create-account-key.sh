#! /usr/bin/env bash

[ -f secrets/account_key.pem ] || openssl genrsa 4096 >account_key.pem
