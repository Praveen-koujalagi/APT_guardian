require("@nomicfoundation/hardhat-toolbox");
module.exports = {
  solidity: "0.8.24",
  networks: {
    // Built-in in-process network for tests
    hardhat: { chainId: 31337 },
    // Standard localhost mapping (when running node directly on host)
    localhost: { url: "http://127.0.0.1:8545", chainId: 31337 },
    // Docker bridge access from sibling containers (Hardhat node runs in service named 'hardhat')
    docker: { url: "http://hardhat:8545", chainId: 31337 }
  }
};
