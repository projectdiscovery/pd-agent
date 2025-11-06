#!/bin/bash

docker build -t openssh-server .
docker run -p 22222:22 openssh-server
