#!/bin/bash
echo "Starting PEP API Service"

while ! nc -z redis 6379; do
  echo "Waiting for Redis..."
  sleep 2
done

./pep_api_service

