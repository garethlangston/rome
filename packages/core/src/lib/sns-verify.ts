import { createVerify } from "node:crypto";

// Verifies an Amazon SNS HTTP(S) message signature, per
// https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html

export interface SnsMessage {
  Type?: string;
  MessageId?: string;
  TopicArn?: string;
  Subject?: string;
  Message?: string;
  Timestamp?: string;
  Token?: string;
  SubscribeURL?: string;
  SignatureVersion?: string;
  Signature?: string;
  SigningCertURL?: string;
}

const SIGNED_FIELDS: Record<string, string[]> = {
  Notification: ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"],
  SubscriptionConfirmation: [
    "Message",
    "MessageId",
    "SubscribeURL",
    "Timestamp",
    "Token",
    "TopicArn",
    "Type",
  ],
  UnsubscribeConfirmation: [
    "Message",
    "MessageId",
    "SubscribeURL",
    "Timestamp",
    "Token",
    "TopicArn",
    "Type",
  ],
};

const certCache = new Map<string, string>();

/** True only for an https URL on `sns.<region>.amazonaws.com` with no port or credentials. */
export function isSnsUrl(raw: unknown, region: string, pathSuffix?: string): boolean {
  if (typeof raw !== "string") return false;
  try {
    const url = new URL(raw);
    return (
      url.protocol === "https:" &&
      url.hostname === `sns.${region}.amazonaws.com` &&
      url.port === "" &&
      !url.username &&
      !url.password &&
      (!pathSuffix || url.pathname.endsWith(pathSuffix))
    );
  } catch {
    return false;
  }
}

async function fetchCert(url: string): Promise<string> {
  const cached = certCache.get(url);
  if (cached) return cached;
  const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`SNS signing certificate fetch failed (${res.status})`);
  const pem = await res.text();
  certCache.set(url, pem);
  return pem;
}

/** Resolves when `msg` carries a valid SNS signature; rejects otherwise. */
export async function verifySnsSignature(
  msg: SnsMessage,
  region: string,
  getCert: (url: string) => Promise<string> = fetchCert,
): Promise<void> {
  const fields = SIGNED_FIELDS[msg.Type ?? ""];
  if (!fields) throw new Error("unsupported SNS message type");
  const algorithm =
    msg.SignatureVersion === "1" ? "SHA1" : msg.SignatureVersion === "2" ? "SHA256" : "";
  if (!algorithm) throw new Error("unsupported SNS signature version");
  if (!msg.Signature) throw new Error("missing SNS signature");
  if (!isSnsUrl(msg.SigningCertURL, region, ".pem")) throw new Error("untrusted SigningCertURL");

  const toSign = fields
    .filter((key) => key !== "Subject" || msg.Subject !== undefined)
    .map((key) => `${key}\n${msg[key as keyof SnsMessage] ?? ""}\n`)
    .join("");
  const cert = await getCert(msg.SigningCertURL as string);
  const ok = createVerify(algorithm).update(toSign, "utf8").verify(cert, msg.Signature, "base64");
  if (!ok) throw new Error("SNS signature mismatch");
}
