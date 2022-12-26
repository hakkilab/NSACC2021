#!/usr/bin/env bash

unzip -o -d ./emails emails.zip

if [ ! -d "./attachments" ] 
then
    mkdir ./attachments
fi

cd ./attachments

for file in ../emails/*
do
    munpack -f $file
done
