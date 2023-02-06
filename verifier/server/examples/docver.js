const { Poseidon } = require("@iden3/js-crypto");

// TODO: change to use the kaleido repo main branch before merging
const SCHEMA_URL =
  "https://raw.githubusercontent.com/nedgar/kaleido-iden3-samples/docver-schema/identity/schemas/docver.json-ld";

const utf8 = (str) => new TextEncoder().encode(str);

const docStatusHash = (...args) => Poseidon.hashBytes(utf8(args.join(":")));

const passportCheck = {
  // The credentialAtomicQuerySig circuit is currently limited to checking a single slot,
  // so we combine the doc ID and status in a single index slot.
  // TODO: separate doc ID and status into separate claim slots (index and value, respectively).
  allowedIssuers: ["*"],
  schema: {
    url: SCHEMA_URL,
    type: "DocumentStatus",
  },
  req: {
    docStatusHash: {
      $eq: docStatusHash("PASSPORT/CA/ZZ123456789", "VERIFIED").toString(),
    },
  },
};

module.exports = { passportCheck };
