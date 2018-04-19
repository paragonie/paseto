#!/usr/bin/env bash

mmark -xml2 -page paseto.md > draft-paragon-paseto-rfc-01.xml
xml2rfc --text draft-paragon-paseto-rfc-01.xml
rm draft-paragon-paseto-rfc-01.xml

