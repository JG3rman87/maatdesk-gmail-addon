#!/bin/bash

if [ "$1" == "dev" ]
then
    echo "Preparing files for development environment"
    cp .clasp-dev.json .clasp.json
elif [ "$1" == "prod" ]
then
    echo "Preparing files for production environment"
    cp .clasp-prod.json .clasp.json
else
    echo "Usage: prepare [dev|prod]"
    exit 1
fi