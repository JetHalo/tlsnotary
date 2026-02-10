import http from "node:http";
import { createRequire } from "node:module";
import { URL } from "node:url";
import {
  asRecord,
  buildWiseReceiptHash,
  extractNotaryPublicKeyPem,
  extractNotaryUrl,
  extractPublicKeyFromNotaryInfo,
  extractRecentTransfers,
  hostMatchesAllowedSuffix,
  normalizeVerifierData,
  parseAllowedHostSuffixes,
  validateExpected,
  verifyPresentationLocally
} from "./lib.js";

const require = createRequire(import.meta.url);
const { verify_presentation: verifyPresentation } = require("@dylan1951/tlsn-ts");

const PORT = Number(process.env.PORT || 8080);
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES || 2_000_000);
const ALLOWED_HOST_SUFFIXES = parseAllowedHostSuffixes(process.env.TLSN_ALLOWED_HOST_SUFFIXES);
const CORS_ALLOW_ORIGIN = process.env.CORS_ALLOW_ORIGIN || "*";
const notaryKeyCache = new Map();

function isBrowserCaptureAttestation(attestation) {
  const view = asRecord(attestation);
  return view.kind === "wise_browser_capture_v1";
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("cache-control", "no-store");
  res.end(body);
}

function setCorsHeaders(res) {
  res.setHeader("access-control-allow-origin", CORS_ALLOW_ORIGIN);
  res.setHeader("access-control-allow-methods", "GET,POST,OPTIONS");
  res.setHeader("access-control-allow-headers", "content-type,authorization");
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let body = "";
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("payload too large"));
        req.destroy();
        return;
      }
      body += chunk;
    });
    req.on("end", () => {
      if (!body.trim()) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("invalid json body"));
      }
    });
    req.on("error", reject);
  });
}

function normalizeAndValidate(raw, payload, availableKeys) {
  const normalized = normalizeVerifierData(raw);
  const missing = [];
  if (!normalized.amount) missing.push("amount missing");
  if (!normalized.timestamp) missing.push("timestamp missing");
  if (!normalized.payerRef) missing.push("payerRef missing");
  if (!normalized.transferId) missing.push("transferId missing");
  if (!normalized.sourceHost) missing.push("sourceHost missing");
  if (missing.length > 0) {
    return {
      ok: false,
      status: 400,
      json: {
        error: "verifier output missing required Wise fields",
        details: missing,
        availableKeys
      }
    };
  }

  if (!hostMatchesAllowedSuffix(normalized.sourceHost, ALLOWED_HOST_SUFFIXES)) {
    return {
      ok: false,
      status: 400,
      json: {
        error: "sourceHost is not an allowed Wise domain",
        details: [`sourceHost=${normalized.sourceHost}`, `allowed=${ALLOWED_HOST_SUFFIXES.join(",")}`],
        availableKeys
      }
    };
  }

  const expectedErrors = validateExpected(payload.expected, normalized);
  if (expectedErrors.length > 0) {
    return {
      ok: false,
      status: 400,
      json: {
        error: "expected constraints mismatch",
        details: expectedErrors,
        availableKeys
      }
    };
  }

  return { ok: true, normalized };
}

function findMatchingRecentTransfer(recentTransfers, selectedTransfer) {
  if (!selectedTransfer || typeof selectedTransfer !== "object") return null;
  const sel = asRecord(selectedTransfer);
  const transferId = String(sel.transferId || "").trim();
  const amount = String(sel.amount || "").trim();
  const payerRef = String(sel.payerRef || "").trim();
  const timestamp = Number(sel.timestamp);

  for (const item of recentTransfers) {
    const row = asRecord(item);
    const rowTransferId = String(row.transferId || "").trim();
    if (transferId && rowTransferId && transferId === rowTransferId) return row;
  }

  for (const item of recentTransfers) {
    const row = asRecord(item);
    const sameAmount = amount && String(row.amount || "").trim() === amount;
    const samePayer = payerRef && String(row.payerRef || "").trim() === payerRef;
    const rowTs = Number(row.timestamp);
    const sameTs = Number.isFinite(timestamp) && Number.isFinite(rowTs) ? Math.abs(rowTs - timestamp) <= 60 : false;
    if (sameAmount && (samePayer || sameTs)) return row;
  }

  return null;
}

async function resolveNotaryPublicKeyPem(attestation) {
  const direct = extractNotaryPublicKeyPem(attestation, process.env.TLSN_NOTARY_PUBLIC_KEY_PEM);
  if (direct) return direct;

  const notaryUrl = extractNotaryUrl(attestation);
  if (!notaryUrl) return undefined;

  if (notaryKeyCache.has(notaryUrl)) {
    return notaryKeyCache.get(notaryUrl);
  }

  const resp = await fetch(`${notaryUrl}/info`, { method: "GET" });
  if (!resp.ok) {
    throw new Error(`notary info fetch failed: ${resp.status}`);
  }
  const info = asRecord(await resp.json().catch(() => ({})));
  const key = extractPublicKeyFromNotaryInfo(info);
  if (!key) {
    throw new Error("notary info response missing public key");
  }
  notaryKeyCache.set(notaryUrl, key);
  return key;
}

async function handleVerifyWiseAttestation(req, res) {
  const payload = asRecord(await readJsonBody(req));
  if (!payload.attestation) {
    return sendJson(res, 400, { error: "attestation is required" });
  }

  const attestationRaw = asRecord(payload.attestation);
  if (isBrowserCaptureAttestation(attestationRaw)) {
    const recentCount = Math.max(1, Math.min(10, Math.trunc(Number(payload.recentCount) || 5)));
    const recentTransfers = extractRecentTransfers(attestationRaw, "", recentCount);
    const selectedTransfer = findMatchingRecentTransfer(recentTransfers, payload.selectedTransfer);
    if (payload.selectedTransfer && !selectedTransfer) {
      return sendJson(res, 400, {
        error: "selected transfer not found in recent transfers"
      });
    }

    const fallbackRow = selectedTransfer ?? asRecord(payload.selectedTransfer) ?? asRecord(recentTransfers[0]);
    const raw = {
      ...attestationRaw,
      amount: fallbackRow.amount ?? attestationRaw.amount,
      timestamp: fallbackRow.timestamp ?? attestationRaw.timestamp,
      payerRef: fallbackRow.payerRef ?? attestationRaw.payerRef,
      transferId: fallbackRow.transferId ?? attestationRaw.transferId,
      sourceHost: attestationRaw.sourceHost ?? "wise.com",
      verified: true
    };
    const availableKeys = Object.keys(raw);

    const normalizedCheck = normalizeAndValidate(raw, payload, availableKeys);
    if (!normalizedCheck.ok) {
      return sendJson(res, normalizedCheck.status, normalizedCheck.json);
    }

    const normalized = normalizedCheck.normalized;
    const wiseReceiptHash = buildWiseReceiptHash(normalized, payload.attestation);

    return sendJson(res, 200, {
      verified: true,
      wiseReceiptHash,
      normalized: {
        amount: normalized.amount,
        timestamp: Math.trunc(normalized.timestamp),
        payerRef: normalized.payerRef,
        transferId: normalized.transferId,
        sourceHost: normalized.sourceHost
      },
      recentTransfers,
      verifier: {
        status: "ok-browser-capture",
        availableKeys,
        tlsVerified: false,
        selectedMatched: Boolean(selectedTransfer),
        warning: "browser capture mode: TLS cryptographic verification is bypassed"
      }
    });
  }

  let notaryPublicKeyPem;
  try {
    notaryPublicKeyPem = await resolveNotaryPublicKeyPem(payload.attestation);
  } catch (error) {
    return sendJson(res, 400, {
      error: "failed to resolve notary public key",
      details: [String(error?.message || error)]
    });
  }
  if (!notaryPublicKeyPem) {
    return sendJson(res, 400, {
      error:
        "missing notary key; include attestation.notaryUrl or set TLSN_NOTARY_PUBLIC_KEY_PEM"
    });
  }

  let localVerification;
  try {
    localVerification = await verifyPresentationLocally({
      attestation: payload.attestation,
      notaryPublicKeyPem,
      verifyPresentation
    });
  } catch (error) {
    return sendJson(res, 400, {
      error: "local tlsn verification failed",
      details: [String(error?.message || error)]
    });
  }

  const recentCount = Math.max(1, Math.min(10, Math.trunc(Number(payload.recentCount) || 5)));
  const recentTransfers = extractRecentTransfers(attestationRaw, localVerification.recv, recentCount);
  const selectedTransfer = findMatchingRecentTransfer(recentTransfers, payload.selectedTransfer);
  if (payload.selectedTransfer && !selectedTransfer) {
    return sendJson(res, 400, {
      error: "selected transfer not found in recent transfers"
    });
  }

  const baseSourceHost = localVerification.serverName ?? attestationRaw.sourceHost ?? attestationRaw.host;
  const baseTimestamp = localVerification.timestamp ?? attestationRaw.timestamp;

  const raw = {
    ...attestationRaw,
    ...(selectedTransfer
      ? {
          amount: selectedTransfer.amount ?? attestationRaw.amount,
          timestamp: selectedTransfer.timestamp ?? baseTimestamp,
          payerRef: selectedTransfer.payerRef ?? attestationRaw.payerRef,
          transferId: selectedTransfer.transferId ?? attestationRaw.transferId
        }
      : {}),
    sourceHost: baseSourceHost,
    timestamp: selectedTransfer?.timestamp ?? baseTimestamp,
    verified: true,
    sent: localVerification.sent,
    recv: localVerification.recv
  };
  const availableKeys = Object.keys(raw);

  const normalizedCheck = normalizeAndValidate(raw, payload, availableKeys);
  if (!normalizedCheck.ok) {
    return sendJson(res, normalizedCheck.status, normalizedCheck.json);
  }

  const normalized = normalizedCheck.normalized;
  const wiseReceiptHash =
    typeof raw.wiseReceiptHash === "string" && raw.wiseReceiptHash.startsWith("0x")
      ? raw.wiseReceiptHash
      : buildWiseReceiptHash(normalized, payload.attestation);

  return sendJson(res, 200, {
    verified: true,
    wiseReceiptHash,
    normalized: {
      amount: normalized.amount,
      timestamp: Math.trunc(normalized.timestamp),
      payerRef: normalized.payerRef,
      transferId: normalized.transferId,
      sourceHost: normalized.sourceHost
    },
    recentTransfers,
    verifier: {
      status: "ok-local",
      availableKeys,
      serverName: localVerification.serverName ?? null,
      selectedMatched: Boolean(selectedTransfer)
    }
  });
}

const server = http.createServer(async (req, res) => {
  setCorsHeaders(res);
  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    res.end();
    return;
  }

  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  try {
    if (req.method === "GET" && url.pathname === "/health") {
      return sendJson(res, 200, { ok: true, service: "tlsn-verifier" });
    }
    if (req.method === "POST" && url.pathname === "/verify-wise-attestation") {
      return await handleVerifyWiseAttestation(req, res);
    }
    return sendJson(res, 404, { error: "not found" });
  } catch (error) {
    return sendJson(res, 500, { error: "internal error", detail: String(error?.message || error) });
  }
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[tlsn-verifier] listening on :${PORT}`);
});
