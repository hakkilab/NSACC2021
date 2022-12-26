#!/usr/bin/env bash

sudo docker image load -i ./image.tar
sudo docker image inspect panic-nightly-test > inspect.json
