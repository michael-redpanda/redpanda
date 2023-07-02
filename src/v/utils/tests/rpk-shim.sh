#!/usr/bin/env bash

TIMEOUT=5

if [ "$1" != "debug" ]; then
  echo "Invalid first param $1"
  exit 1
fi

if [ "$2" != "bundle" ]; then
  echo "Invalid second param $2"
  exit 1
fi

options=$(getopt -o "" --longoptions logs-since:,logs-until:,logs-size-limit:,metrics-interval:,username:,password:,mechanism:,tls-enabled,output: -- "${@:3}")

[ $? -eq 0 ] || {
  echo "Incorrect options provided"
  exit 1
}

eval set -- "$options"

tls_enabled=false

while true; do
  case "$1" in
    --logs-since)
      logs_since="$2"
      shift 2
      ;;
    --logs-until)
      logs_until="$2"
      shift 2
      ;;
    --logs-size-limit)
      logs_size_limit="$2"
      shift 2
      ;;
    --metrics-interval)
      metrics_interval="$2"
      shift 2
      ;;
    --username)
      username="$2"
      shift 2
      ;;
    --password)
      password="$2"
      shift 2
      ;;
    --mechanism)
      mechanism="$2"
      shift 2
      ;;
    --output)
      output_file="$2"
      shift 2
      ;;
    --tls-enabled)
      tls_enabled=true
      shift 1
      ;;
    *)
      break
      ;;
  esac
done

cat >$output_file <<EOF
$logs_since
$logs_until
$logs_size_limit
$metrics_interval
$username
$password
$mechanism
$output_file
$tls_enabled
EOF

sleep $TIMEOUT
