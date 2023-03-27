require('@nomiclabs/hardhat-ethers');
require('@openzeppelin/hardhat-upgrades');

const networks = {};

if (process.env.KALEIDO_NODE_URL) {
  networks.kaleido = {
    url: process.env.KALEIDO_NODE_URL
  };
}


if (process.env.MUMBAI_NODE_URL) {
  networks.mumbai = {
    url: process.env.MUMBAI_NODE_URL,
    accounts: [process.env.MUMBAI_PRIV_KEY]
  };
}
/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  networks,
  solidity: {
    compilers: [
      {
        version: '0.8.15',
      },
      {
        version: '0.6.11',
      },
    ],
  },
};
