const { ageCheck } = require("./kyc");
const { passportCheck } = require("./docver");

module.exports = {
    kyc_age: ageCheck,
    docver_passport: passportCheck,
};
