require('@nomiclabs/hardhat-ethers');
require('@openzeppelin/hardhat-upgrades');

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  networks: {
    kaleido: {
      url: process.env.KALEIDO_NODE_URL,
    },
    mumbai: {
      url: process.env.MUMBAI_NODE_URL,
      accounts: [process.env.MUMBAI_PRIV_KEY],
    },
  },
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
