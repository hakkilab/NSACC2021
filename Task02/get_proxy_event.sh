#!/usr/bin/env bash

grep '#Date' proxy.log > proxy_event.txt
grep -E '198\.18\.159\.74|10\.78\.211\.175' proxy.log >> proxy_event.txt
