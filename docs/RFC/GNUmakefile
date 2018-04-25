FORMATS := html txt

.PHONY: all clean
all: $(foreach ext,$(FORMATS),draft-paragon-paseto-rfc-01.$(ext))

clean:
	rm -f $(foreach ext,$(FORMATS) xml,draft-paragon-paseto-rfc-01.$(ext))

draft-paragon-paseto-rfc-01.xml: paseto.md
	mmark -xml2 -page $< $@

%.txt: %.xml
	xml2rfc --text $<

%.html: %.xml
	xml2rfc --html $<
