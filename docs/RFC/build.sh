#!/usr/bin/env bash

mmark -xml2 -page paseto.md > draft-paragonie-paseto-rfc-00.xml
xml2rfc --text draft-paragonie-paseto-rfc-00.xml
rm draft-paragonie-paseto-rfc-00.xml

