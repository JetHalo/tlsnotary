import test from "node:test";
import assert from "node:assert/strict";
import {
  buildWiseReceiptHash,
  extractNotaryPublicKeyPem,
  extractNotaryUrl,
  extractPublicKeyFromNotaryInfo,
  extractRecentTransfers,
  extractPresentationHex,
  hostMatchesAllowedSuffix,
  normalizeVerifierData,
  parseAllowedHostSuffixes,
  verifyPresentationLocally
} from "../src/lib.js";

test("hostMatchesAllowedSuffix accepts subdomains", () => {
  const allowed = parseAllowedHostSuffixes("wise.com,transferwise.com");
  assert.equal(hostMatchesAllowedSuffix("wise.com", allowed), true);
  assert.equal(hostMatchesAllowedSuffix("api.wise.com", allowed), true);
  assert.equal(hostMatchesAllowedSuffix("evilwise.com", allowed), false);
});

test("normalizeVerifierData extracts required fields", () => {
  const normalized = normalizeVerifierData({
    verified: true,
    amount: "1000000",
    timestamp: 1739102400,
    payer: "payer-a",
    transferId: "tx-1",
    sourceHost: "wise.com"
  });

  assert.equal(normalized.amount, "1000000");
  assert.equal(normalized.timestamp, 1739102400);
  assert.equal(normalized.payerRef, "payer-a");
  assert.equal(normalized.transferId, "tx-1");
  assert.equal(normalized.sourceHost, "wise.com");
});

test("buildWiseReceiptHash is deterministic", () => {
  const normalized = {
    amount: "1000000",
    timestamp: 1739102400,
    payerRef: "payer-a",
    transferId: "tx-1",
    sourceHost: "wise.com"
  };
  const attestation = { a: 1, b: "2" };
  const a = buildWiseReceiptHash(normalized, attestation);
  const b = buildWiseReceiptHash(normalized, attestation);
  assert.equal(a, b);
  assert.equal(a.startsWith("0x"), true);
});

test("extractPresentationHex supports tlsn-js presentation envelope", () => {
  const value = extractPresentationHex({
    version: "0.1.0-alpha.12",
    data: "0xdeadbeef"
  });
  assert.equal(value, "deadbeef");
});

test("extractNotaryPublicKeyPem prefers attestation key then env fallback", () => {
  const keyA = extractNotaryPublicKeyPem(
    { notaryKeyPem: "-----BEGIN PUBLIC KEY-----\nA\n-----END PUBLIC KEY-----" },
    "-----BEGIN PUBLIC KEY-----\nB\n-----END PUBLIC KEY-----"
  );
  const keyB = extractNotaryPublicKeyPem({}, "-----BEGIN PUBLIC KEY-----\nB\n-----END PUBLIC KEY-----");
  assert.match(keyA, /BEGIN PUBLIC KEY/);
  assert.match(keyB, /BEGIN PUBLIC KEY/);
});

test("verifyPresentationLocally returns normalized local verify output", async () => {
  const result = await verifyPresentationLocally({
    attestation: { presentation: "0xabc123" },
    notaryPublicKeyPem: "-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----",
    verifyPresentation: () => ({
      sent: "GET / HTTP/1.1",
      recv: "HTTP/1.1 200 OK",
      time: 1739102400n,
      server_name: "api.wise.com"
    })
  });

  assert.equal(result.serverName, "api.wise.com");
  assert.equal(result.timestamp, 1739102400);
  assert.match(result.sent, /GET/);
  assert.match(result.recv, /200/);
});

test("extractNotaryUrl picks url from meta first", () => {
  const url = extractNotaryUrl({
    notaryUrl: "https://ignored.notary",
    meta: {
      notaryUrl: "https://notary.example"
    }
  });
  assert.equal(url, "https://notary.example");
});

test("extractPublicKeyFromNotaryInfo supports common key fields", () => {
  assert.match(
    extractPublicKeyFromNotaryInfo({
      publicKey: "-----BEGIN PUBLIC KEY-----\nA\n-----END PUBLIC KEY-----"
    }),
    /BEGIN PUBLIC KEY/
  );
  assert.match(
    extractPublicKeyFromNotaryInfo({
      public_key: "-----BEGIN PUBLIC KEY-----\nB\n-----END PUBLIC KEY-----"
    }),
    /BEGIN PUBLIC KEY/
  );
});

test("extractRecentTransfers parses top 5 transfers from recv json", () => {
  const recv = [
    "HTTP/1.1 200 OK",
    "content-type: application/json",
    "",
    JSON.stringify({
      transactions: [
        { id: "t1", amount: "10", timestamp: 1, payer: "a" },
        { id: "t2", amount: "20", timestamp: 2, payer: "b" },
        { id: "t3", amount: "30", timestamp: 3, payer: "c" },
        { id: "t4", amount: "40", timestamp: 4, payer: "d" },
        { id: "t5", amount: "50", timestamp: 5, payer: "e" },
        { id: "t6", amount: "60", timestamp: 6, payer: "f" }
      ]
    })
  ].join("\r\n");

  const recent = extractRecentTransfers({}, recv, 5);
  assert.equal(recent.length, 5);
  assert.equal(recent[0].transferId, "t1");
  assert.equal(recent[4].transferId, "t5");
});
