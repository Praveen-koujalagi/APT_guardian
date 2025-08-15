const fs = require("fs");
const path = require("path");
const { ethers } = require("hardhat");
const hre = require("hardhat");
async function main() {
  console.log("[Deploy] Script start");
  console.log("[Deploy] Network:", hre.network.name);
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with:", deployer.address);
  const Factory = await ethers.getContractFactory("IncidentLog");
  const contract = await Factory.deploy();
  await contract.deployed();
  console.log("IncidentLog deployed to:", contract.address);

  // Write address + ABI for the Python client
  const artifactPath = path.join(__dirname, "..", "artifacts", "contracts", "IncidentLog.sol", "IncidentLog.json");
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const outDir = path.join(__dirname, "..", "deployments", "localhost");
  fs.mkdirSync(outDir, { recursive: true });
  const out = {
    address: contract.address,
    abi: artifact.abi
  };
  const outPath = path.join(outDir, "IncidentLog.json");
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
  console.log("Wrote:", outPath);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
