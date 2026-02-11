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
  const transferId = pickString(view, [
    "transferId",
    "paymentId",
    "transactionId",
    "transactionNumber",
    "transactionNo",
    "transaction_number",
    "id",
    "reference"
  ]);
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

  if (
    typeof expected.transferId === "string" &&
    expected.transferId.trim() &&
    typeof normalized.transferId === "string" &&
    normalized.transferId.trim() &&
    expected.transferId.trim() !== normalized.transferId.trim()
  ) {
    errors.push(`transferId mismatch: expected=${expected.transferId}, actual=${normalized.transferId}`);
  }

  if (
    typeof expected.payerRef === "string" &&
    expected.payerRef.trim() &&
    typeof normalized.payerRef === "string" &&
    normalized.payerRef.trim() &&
    expected.payerRef.trim() !== normalized.payerRef.trim()
  ) {
    errors.push(`payerRef mismatch: expected=${expected.payerRef}, actual=${normalized.payerRef}`);
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

function toFiniteNumber(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value.trim());
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function toUnixSeconds(value) {
  const finite = toFiniteNumber(value);
  if (Number.isFinite(finite)) {
    const normalized = finite > 1_000_000_000_000 ? finite / 1000 : finite;
    return Math.trunc(normalized);
  }
  if (typeof value === "string" && value.trim()) {
    const parsedDate = Date.parse(value.trim());
    if (Number.isFinite(parsedDate)) return Math.trunc(parsedDate / 1000);
  }
  return undefined;
}

function tryParseJson(text) {
  if (typeof text !== "string") return undefined;
  const trimmed = text.trim();
  if (!trimmed) return undefined;
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

function extractJsonBodiesFromRecv(recv) {
  const text = String(recv || "");
  if (!text) return [];
  const candidates = new Set();

  const sections = text.split(/\r?\n\r?\n/g).map((s) => s.trim()).filter(Boolean);
  for (const part of sections) {
    if (part.startsWith("{") || part.startsWith("[")) candidates.add(part);
  }

  const firstObject = text.indexOf("{");
  const lastObject = text.lastIndexOf("}");
  if (firstObject >= 0 && lastObject > firstObject) {
    candidates.add(text.slice(firstObject, lastObject + 1));
  }

  const firstArray = text.indexOf("[");
  const lastArray = text.lastIndexOf("]");
  if (firstArray >= 0 && lastArray > firstArray) {
    candidates.add(text.slice(firstArray, lastArray + 1));
  }

  const parsed = [];
  for (const candidate of candidates) {
    const value = tryParseJson(candidate);
    if (value !== undefined) parsed.push(value);
  }
  return parsed;
}

function flattenArrays(value, out = []) {
  if (Array.isArray(value)) {
    out.push(value);
    for (const item of value) flattenArrays(item, out);
    return out;
  }
  if (value && typeof value === "object") {
    for (const key of Object.keys(value)) {
      flattenArrays(value[key], out);
    }
  }
  return out;
}

function normalizeTransferItem(item) {
  const row = asRecord(item);
  if (Object.keys(row).length === 0) return undefined;

  const amount =
    pickString(row, ["amount", "amountText", "value", "paymentAmount", "transferAmount"]) ??
    pickString(asRecord(row.amount), ["value", "text", "amount", "formatted"]);
  const timestampRaw =
    pickNumber(row, ["timestamp", "time", "createdAtTs", "created_at_ts"]) ??
    pickString(row, ["createdAt", "created_at", "paidAt", "date", "time"]);
  const payerRef =
    pickString(row, ["payerRef", "payer", "sender", "from", "counterparty", "name"]) ??
    pickString(asRecord(row.sender), ["name", "id"]) ??
    pickString(asRecord(row.counterparty), ["name", "id"]);
  const transferText =
    pickString(row, ["description", "details", "title", "note"]) ??
    pickString(asRecord(row.transaction), ["description", "details", "title", "note"]) ??
    "";
  const transferNumber = /transaction\s*(?:number|id)?\s*#?\s*([0-9]{6,})/i.exec(transferText)?.[1];
  const transferId =
    pickString(row, [
      "transferId",
      "paymentId",
      "transactionId",
      "transactionNumber",
      "transactionNo",
      "transaction_number",
      "id",
      "reference"
    ]) ??
    pickString(asRecord(row.transaction), [
      "id",
      "reference",
      "transactionId",
      "transactionNumber",
      "transactionNo"
    ]) ??
    transferNumber;
  const status = pickString(row, ["status", "state", "paymentStatus"]);
  const currency = pickString(row, ["currency", "ccy"]) ?? pickString(asRecord(row.amount), ["currency", "ccy"]);

  if (!amount && !transferId && !payerRef) return undefined;
  return {
    amount: amount ?? "",
    timestamp: toUnixSeconds(timestampRaw),
    payerRef: payerRef ?? "",
    transferId: transferId ?? "",
    status: status ?? "",
    currency: currency ?? ""
  };
}

export function extractRecentTransfers(attestation, recv, limit = 5) {
  const max = Math.max(1, Math.min(10, Math.trunc(Number(limit) || 5)));
  const roots = [];

  const attestationRecord = asRecord(attestation);
  if (Object.keys(attestationRecord).length > 0) {
    roots.push(attestationRecord);
    roots.push(asRecord(attestationRecord.claimData));
    roots.push(asRecord(attestationRecord.data));
    roots.push(asRecord(attestationRecord.fields));
  }

  const recvJson = extractJsonBodiesFromRecv(recv);
  for (const value of recvJson) roots.push(value);

  const seen = new Set();
  const result = [];

  for (let rootIndex = 0; rootIndex < roots.length; rootIndex++) {
    const root = roots[rootIndex];
    const arrays = flattenArrays(root);
    for (let arrIndex = 0; arrIndex < arrays.length; arrIndex++) {
      const arr = arrays[arrIndex];
      for (let itemIndex = 0; itemIndex < arr.length; itemIndex++) {
        const item = arr[itemIndex];
        const normalized = normalizeTransferItem(item);
        if (!normalized) continue;
        const keyBase = `${normalized.transferId}|${normalized.timestamp}|${normalized.amount}|${normalized.payerRef}`;
        const hasStrongId =
          Boolean(normalized.transferId) ||
          (typeof normalized.timestamp === "number" && Number.isFinite(normalized.timestamp));
        const key = hasStrongId
          ? keyBase
          : `${keyBase}|row:${rootIndex}:${arrIndex}:${itemIndex}`;
        if (seen.has(key)) continue;
        seen.add(key);
        result.push(normalized);
        if (result.length >= max) return result;
      }
    }
  }

  return result;
}
