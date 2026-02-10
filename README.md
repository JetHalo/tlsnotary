# tlsn-verifier (Railway Deployable)

Standalone verifier service for Wise TLS attestation.
This service verifies TLSN presentation locally (inside this service), then enforces Wise domain + expected constraints.

## Endpoints
- `GET /health`
- `POST /verify-wise-attestation`

## Request
```json
{
  "proofId": "proof-123",
  "attestation": { "..." : "..." },
  "expected": {
    "amount": "1000000",
    "timestamp": 1739102400
  }
}
```

### Attestation format requirement
- The payload must contain TLSN presentation bytes in hex form (`0x...` or hex), for example in one of:
  - `attestation.presentationHex`
  - `attestation.presentation`
  - `attestation.data`
- Notary public key can come from:
  - `attestation.notaryPublicKeyPem` (or similar key alias), or
  - env `TLSN_NOTARY_PUBLIC_KEY_PEM`.

## Response
```json
{
  "verified": true,
  "wiseReceiptHash": "0x...",
  "normalized": {
    "amount": "1000000",
    "timestamp": 1739102400,
    "payerRef": "xxxx",
    "transferId": "xxxx",
    "sourceHost": "wise.com"
  },
  "verifier": {
    "status": "ok-local",
    "availableKeys": ["..."]
  }
}
```

## Local run
```bash
cd apps/tlsn-verifier
npm install
npm run dev
```

## Railway deploy
1. Connect GitHub repo.
2. Create a new service.
3. Set Root Directory to `apps/tlsn-verifier`.
4. Build command: `npm install`
5. Start command: `npm run start`
6. Set env vars from `.env.example`.

## Required env
- None (service can auto-fetch notary public key from `attestation.meta.notaryUrl/info`)

## Optional env
- `TLSN_NOTARY_PUBLIC_KEY_PEM` (override/fallback notary public key PEM)
- `TLSN_ALLOWED_HOST_SUFFIXES` (default: `wise.com,transferwise.com`)
- `CORS_ALLOW_ORIGIN` (default: `*`)
