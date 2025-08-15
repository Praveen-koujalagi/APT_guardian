const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');

async function main() {
  const RPC = process.env.RPC_URL || 'http://hardhat:8545';
  console.log('[RawDeploy] RPC_URL =', RPC);
  const provider = new ethers.JsonRpcProvider(RPC);
  const accounts = await provider.listAccounts();
  if (!accounts.length) throw new Error('No accounts returned by provider');
  const deployer = accounts[0];
  console.log('[RawDeploy] Using account', deployer);
  const signer = provider.getSigner(deployer);
  const artifactPath = path.join(__dirname, '..', 'artifacts', 'contracts', 'IncidentLog.sol', 'IncidentLog.json');
  const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
  console.log('[RawDeploy] Artifact loaded, bytecode size:', artifact.bytecode.length / 2 - 1, 'bytes');
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, signer);
  console.log('[RawDeploy] Deploying...');
  const contract = await factory.deploy();
  if (contract.deployed) await contract.deployed();
  if (contract.waitForDeployment) await contract.waitForDeployment();
  const address = contract.address || (await contract.getAddress());
  console.log('[RawDeploy] Deployed IncidentLog at', address);
  const outDir = path.join(__dirname, '..', 'deployments', 'localhost');
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, 'IncidentLog.json');
  fs.writeFileSync(outPath, JSON.stringify({ address, abi: artifact.abi }, null, 2));
  console.log('[RawDeploy] Wrote', outPath);
}

main().catch(err => { console.error('[RawDeploy] ERROR', err); process.exit(1); });
