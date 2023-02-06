const SCHEMA_URL = "https://schema.polygonid.com/jsonld/kyc.json-ld";

const ageCheck = {
  allowedIssuers: ["*"],
  schema: {
    url: SCHEMA_URL,
    type: "AgeCredential",
  },
  req: {
    birthDay: {
      $lt: 20000101, // birthDay prior to 2000/01/01
    },
  },
};

module.exports = { ageCheck };
