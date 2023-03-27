--------------------------------------------------------------------------------
-- Up
--------------------------------------------------------------------------------

CREATE TABLE Identities (
  identifier TEXT PRIMARY KEY,
  state      TEXT NULL,
  published  BOOL NULL DEFAULT false,
  genesis    BOOL NULL DEFAULT false
);

CREATE TABLE Profiles (
  id                TEXT PRIMARY KEY,
  nonce             INTEGER NOT NULL,
  genesisIdentifier TEXT NULL,
  verifier          TEXT NULL
);

CREATE TABLE Credentials (
  id                TEXT PRIMARY KEY,
  context           TEXT NOT NULL,
  credentialType    TEXT NOT NULL,
  expirationDate    TEXT NULL,
  issuanceDate      TEXT NULL,
  credentialSchema  TEXT NOT NULL,
  credentialSubject TEXT NOT NULL,
  credentialStatus  TEXT NOT NULL,
  issuer            TEXT NOT NULL,
  proof             TEXT NOT NULL
);
