import crypto from "node:crypto";

export function sha256Hex(value) {
  return `0x${crypto.createHash("sha256").update(value).digest("hex")}`;
}

export function asRecord(value) {
  if (!value || typeof value !== "object") return {};
  return value;
}

function isHexText(value) {
  return /^[0-9a-fA-F]+$/.test(value);
}

export function normalizeHexString(value) {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  if (trimmed.startsWith("0x") && isHexText(trimmed.slice(2))) {
    return trimmed.slice(2).toLowerCase();
  }
  if (isHexText(trimmed)) {
    return trimmed.toLowerCase();
  }
  return undefined;
}

function maybeParseJsonString(value) {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return undefined;
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

export function pickString(input, keys) {
  for (const key of keys) {
    const value = input[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

export function pickNumber(input, keys) {
  for (const key of keys) {
    const value = input[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && value.trim()) {
      const parsed = Number(value.trim());
      if (Number.isFinite(parsed)) return parsed;
    }
  }
  return undefined;
}

export function extractPresentationHex(attestation, depth = 0) {
  if (depth > 5) return undefined;
  const direct = normalizeHexString(attestation);
  if (direct) return direct;

  const parsed = maybeParseJsonString(attestation);
  if (parsed) {
    const nested = extractPresentationHex(parsed, depth + 1);
    if (nested) return nested;
  }

  const record = asRecord(attestation);
  if (Object.keys(record).length === 0) return undefined;

  const candidateKeys = [
    "presentationHex",
    "presentation_hex",
    "presentation",
    "proof",
    "proofHex",
    "attestationHex",
    "data"
  ];
  for (const key of candidateKeys) {
    const nested = extractPresentationHex(record[key], depth + 1);
    if (nested) return nested;
  }

  const meta = asRecord(record.meta);
  for (const key of candidateKeys) {
    const nested = extractPresentationHex(meta[key], depth + 1);
    if (nested) return nested;
  }

  return undefined;
}

export function extractNotaryPublicKeyPem(attestation, envFallback = "") {
  const root = asRecord(attestation);
  const meta = asRecord(root.meta);
  const key = pickString(root, [
    "notaryPublicKeyPem",
    "notaryKeyPem",
    "notary_key_pem",
    "notaryPubKeyPem",
    "publicKeyPem"
  ]);
  if (key) return key;

  const metaKey = pickString(meta, [
    "notaryPublicKeyPem",
    "notaryKeyPem",
    "notary_key_pem",
    "notaryPubKeyPem",
    "publicKeyPem"
  ]);
  if (metaKey) return metaKey;

  const fallback = String(envFallback || "").trim();
  return fallback || undefined;
}

export function extractNotaryUrl(attestation) {
  const root = asRecord(attestation);
  const meta = asRecord(root.meta);
  const value =
    pickString(meta, ["notaryUrl", "notary_url", "notary"]) ??
    pickString(root, ["notaryUrl", "notary_url", "notary"]);
  if (!value) return undefined;
  try {
    const normalized = new URL(value).toString();
    return normalized.endsWith("/") ? normalized.slice(0, -1) : normalized;
  } catch {
    return undefined;
  }
}

export function extractPublicKeyFromNotaryInfo(info) {
  const record = asRecord(info);
  return pickString(record, [
    "publicKey",
    "public_key",
    "notaryPublicKeyPem",
    "notary_key_pem"
  ]);
}

export async function verifyPresentationLocally({
  attestation,
  notaryPublicKeyPem,
  verifyPresentation
}) {
  if (typeof verifyPresentation !== "function") {
    throw new Error("verifyPresentation function is required");
  }
  if (!notaryPublicKeyPem || typeof notaryPublicKeyPem !== "string") {
    throw new Error("missing notary public key PEM");
  }

  const presentationHex = extractPresentationHex(attestation);
  if (!presentationHex) {
    throw new Error("unable to extract presentation hex from attestation payload");
  }

  const rawResult = await Promise.resolve(verifyPresentation(presentationHex, notaryPublicKeyPem));
  const sent = typeof rawResult?.sent === "string" ? rawResult.sent : "";
  const recv = typeof rawResult?.recv === "string" ? rawResult.recv : "";
  const serverName = pickString(asRecord(rawResult), ["server_name", "serverName", "sourceHost", "host"]);
  const timestampRaw =
    typeof rawResult?.time === "bigint"
      ? Number(rawResult.time)
      : pickNumber(asRecord(rawResult), ["time", "timestamp"]);
  const timestamp = Number.isFinite(timestampRaw) ? Math.trunc(timestampRaw) : undefined;

  if (rawResult && typeof rawResult.free === "function") {
    rawResult.free();
  }

  return {
    presentationHex,
    sent,
    recv,
    serverName,
    timestamp
  };
}

export function isVerifierSuccess(raw) {
  const flags = [raw.verified, raw.ok, raw.success, raw.valid];
  return flags.some((value) => value === true || value === "true");
}

export function normalizeVerifierData(raw) {
  const nested = asRecord(raw.claimData ?? raw.extracted ?? raw.normalized ?? raw.data ?? raw.fields);
  const view = { ...raw, ...nested };
  const amount = pickString(view, ["amount", "amountText", "transferAmount", "paymentAmount"]);
  const timestamp = pickNumber(view, ["timestamp", "transferTimestamp", "createdAtTs", "paidAt", "time"]);
  const payerRef = pickString(view, [
    "payerRef",
    "payer",
    "sender",
    "payerId",
    "accountHolder",
    "recipientText"
  ]);
  const transferId = pickString(view, ["transferId", "paymentId", "transactionId", "id", "reference"]);
  const sourceHost = pickString(view, ["sourceHost", "host", "domain", "originHost", "server_name"]);

  return {
    amount,
    timestamp,
    payerRef,
    transferId,
    sourceHost
  };
}

export function parseAllowedHostSuffixes(raw) {
  const value = raw ?? "wise.com,transferwise.com";
  return value
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
}

export function hostMatchesAllowedSuffix(host, suffixes) {
  const normalized = String(host || "").trim().toLowerCase();
  return suffixes.some((suffix) => normalized === suffix || normalized.endsWith(`.${suffix}`));
}

export function isUnsignedIntegerText(value) {
  return /^[0-9]+$/.test(String(value || "").trim());
}

export function validateExpected(expected, normalized) {
  const errors = [];
  if (!expected || typeof expected !== "object") return errors;

  if (
    typeof expected.amount === "string" &&
    isUnsignedIntegerText(expected.amount) &&
    isUnsignedIntegerText(normalized.amount) &&
    expected.amount !== normalized.amount
  ) {
    errors.push(`amount mismatch: expected=${expected.amount}, actual=${normalized.amount}`);
  }

  if (typeof expected.timestamp === "number" && Number.isFinite(expected.timestamp)) {
    const lhs = Math.trunc(expected.timestamp);
    const rhs = Math.trunc(Number(normalized.timestamp || 0));
    if (Math.abs(lhs - rhs) > 30 * 60) {
      errors.push(`timestamp out of skew: expected=${lhs}, actual=${rhs}`);
    }
  }

  return errors;
}

export function buildWiseReceiptHash(normalized, attestation) {
  const attestationDigest = sha256Hex(JSON.stringify(attestation));
  return sha256Hex(
    [
      "wise",
      normalized.sourceHost,
      normalized.transferId,
      normalized.payerRef,
      normalized.amount,
      String(Math.trunc(normalized.timestamp)),
      attestationDigest
    ].join("|")
  );
}
