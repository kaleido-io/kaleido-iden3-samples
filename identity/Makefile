IDEN3_DIR = $(HOME)/iden3
IDENTITIES_FILE = $(IDEN3_DIR)/identities.json

JD_ID = $(shell jq -r .JohnDoe $(IDEN3_DIR)/identities.json)
AW_ID = $(shell jq -r .AliceWonder $(IDEN3_DIR)/identities.json)

CLAIM_NONCE = 2
CLAIM_FILENAME = $(CLAIM_NONCE)-$(AW_ID).json
ISSUED_CLAIM_PATH = $(IDEN3_DIR)/JohnDoe/claims/$(CLAIM_FILENAME)
RECEIVED_CLAIMS_DIR = $(IDEN3_DIR)/AliceWonder/received-claims

all: identities issue-claim receive-claim respond-to-challenge

test: identities
	@echo IDEN3_DIR: $(IDEN3_DIR)
	@echo IDENTITIES_FILE: $(IDENTITIES_FILE)
	@echo JD_ID: $(JD_ID)
	@echo AW_ID: $(AW_ID)
	@echo CLAIM_FILENAME: $(CLAIM_FILENAME)
	@echo ISSUED_CLAIM_PATH: $(ISSUED_CLAIM_PATH)
	@echo RECEIVED_CLAIMS_DIR: $(RECEIVED_CLAIMS_DIR)

JohnDoe: $(IDEN3_DIR)/JohnDoe
	@echo "JohnDoe's ID:" $(JD_ID)

AliceWonder: $(IDEN3_DIR)/AliceWonder
	@echo "AliceWonder's ID:" $(AW_ID)

identities: JohnDoe AliceWonder

issue-claim: identities
	go run main.go claim --issuer JohnDoe --holder $(AW_ID) --nonce $(CLAIM_NONCE)

receive-claim: identities
	mkdir -p $(RECEIVED_CLAIMS_DIR)
	cp $(ISSUED_CLAIM_PATH) $(RECEIVED_CLAIMS_DIR)/

respond-to-challenge:
	go run main.go respond-to-challenge --holder AliceWonder --qrcode ~/Downloads/challenge-qr.png

$(IDEN3_DIR)/JohnDoe:
	go run main.go init --name JohnDoe

$(IDEN3_DIR)/AliceWonder:
	go run main.go init --name AliceWonder

clean:
	rm -fr $(IDEN3_DIR)
