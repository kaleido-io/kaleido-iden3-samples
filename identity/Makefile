IDEN3_WORKDIR := $(HOME)/iden3

.PHONY: all
all: success-test

.PHONY: success-test
success-test: identities issue-claim respond-to-challenge

.PHONY: failure-test
failure-test: identities issue-claim-fails-challenge respond-to-challenge

.PHONY: JohnDoe
JohnDoe: $(IDEN3_WORKDIR)/JohnDoe

.PHONY: AliceWonder
AliceWonder: $(IDEN3_WORKDIR)/AliceWonder

.PHONY: identities
identities: JohnDoe AliceWonder

.PHONY: issue-claim
issue-claim: identities
	go run main.go claim --issuer JohnDoe --holder AliceWonder --schemaType AgeCredential --indexDataA 19950704

.PHONY: issue-claim-fails-challenge
issue-claim-fails-challenge: identities
	go run main.go claim --issuer JohnDoe --holder AliceWonder --schemaType AgeCredential --indexDataA 20220704

.PHONY: issue-docver-claim
issue-docver-claim: identities
	go run main.go claim --issuer JohnDoe --holder AliceWonder --schemaFile schemas/docver.json-ld --schemaType DocumentStatus --indexDataA '"PASSPORT/CA/ZZ123456789:VERIFIED"' --expiryDays 90

.PHONY: respond-to-challenge
respond-to-challenge:
	go run main.go respond-to-challenge --holder AliceWonder --qrcode ~/Downloads/challenge-qr.png

$(IDEN3_WORKDIR)/JohnDoe:
	go run main.go init --name JohnDoe

$(IDEN3_WORKDIR)/AliceWonder:
	go run main.go init --name AliceWonder

.PHONY: clean
clean:
	rm -fr $(IDEN3_WORKDIR)

.PHONY: clean-ids
clean-ids:
	cd $(IDEN3_WORKDIR) && rm -fr JohnDoe AliceWonder identities.json

.PHONY: clean-claims
clean-claims:
	cd $(IDEN3_WORKDIR) && rm -fr JohnDoe/private/claims/genericClaim-*.json AliceWonder/private/received-claims/genericClaim-*.json AliceWonder/challenge.json
