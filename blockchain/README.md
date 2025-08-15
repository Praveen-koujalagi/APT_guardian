# Local blockchain (Hardhat)

Run a local dev chain and deploy the `IncidentLog` contract:

```bash
npm install
npx hardhat node
# new terminal (same folder):
npx hardhat run scripts/deploy.js --network localhost
```

The deployed address and ABI will be written to:
`./deployments/localhost/IncidentLog.json`

The ML service reads that file (path configurable via `CONTRACT_JSON`).
