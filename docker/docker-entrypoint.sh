#!/usr/bin/env bash

if [[ ! -f /app/smartdns.conf ]]; then
  echo "File /app/smartdns.conf is empty. It must be set in order to get started You can find additional information
  here:"
  echo "https://pymumu.github.io/smartdns/en/config/basic-config/"
  exit 1
fi

# Init with default parameter
if [[ -z "${PARAMS}" ]];then
  PARAMS="run -c /app/smartdns.conf"
fi
/app/smartdns  $PARAMS
