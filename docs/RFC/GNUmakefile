.PHONY: all clean
all: draft-paragon-paseto-rfc-01.txt

clean:
	rm -f $(foreach ext,txt xml,draft-paragon-paseto-rfc-01.$(ext))

draft-paragon-paseto-rfc-01.xml: paseto.md
	mmark -xml2 -page $< $@

%.txt: %.xml
	xml2rfc --text $<
