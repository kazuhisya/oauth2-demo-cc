#!/bin/bash
docker build -t local/oauth2:cc .
docker build -t local/oauth2:cc-dev -f Dockerfile-dev .
