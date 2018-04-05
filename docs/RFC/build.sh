#!/usr/bin/env bash

mmark -xml2 -page paseto.md > paseto.xml
xml2rfc --text paseto.xml
rm paseto.xml

