require('@nomiclabs/hardhat-ethers');
require('@openzeppelin/hardhat-upgrades');

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  networks: {
    kaleido: {
      url: `${process.env.KALEIDO_NODE_URL}`,
      // gas: 10000000,
      // httpHeaders: {
      //   Authorization: `Basic ${process.env.BASIC_AUTH}`,
      // },
    },
    mumbai: {
      url: 'http://ec2-18-117-125-203.us-east-2.compute.amazonaws.com:8545',
      accounts: ['0x570ca3f6374b7709e68a5f96e25dab2459a7283064b58ad86c0aee9a26ceef70'],
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
