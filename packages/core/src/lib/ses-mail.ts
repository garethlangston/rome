import { createHmac, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";
import { type AddressObject, type ParsedMail, simpleParser } from "mailparser";
import MailComposer from "nodemailer/lib/mail-composer/index.js";
import { createLogger } from "../logger.js";
import { getProfileDir } from "../paths.js";
import {
  type EmailAddress,
  type EmailBodyPart,
  type ListMessagesParams,
  type ListMessagesResult,
  type MailAttachmentDownload,
  type MailAuthentication,
  type MailProvider,
  MailProviderError,
  type ProvisionResult,
  type RomeMailEvent,
  type RomeMailListItem,
  type RomeMailMessage,
  type SendMailInput,
  type SendMailResult,
} from "./rome-cloud-mail.js";
import { type SnsMessage, isSnsUrl, verifySnsSignature } from "./sns-verify.js";

const log = createLogger("ses-mail");

// Amazon SES mail provider: outbound via SESv2 SendEmail (raw MIME), inbound via
// SES receipt rule -> S3 + SNS -> `POST /api/mail/ses/inbound`. Selected by
// ROME_MAIL_PROVIDER=ses; Rome Cloud mail is untouched otherwise.

export interface SesMailConfig {
  address: string;
  guardianEmail?: string;
  topicArn: string;
  bucket: string;
  region: string;
}

const REQUIRED_ENV = [
  "ROME_MAIL_ADDRESS",
  "ROME_SES_TOPIC_ARN",
  "ROME_SES_BUCKET",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_REGION",
] as const;

/** Throws naming every missing variable. Values are never echoed. */
export function sesMailConfigFromEnv(env: NodeJS.ProcessEnv): SesMailConfig {
  const missing = REQUIRED_ENV.filter((name) => !env[name]?.trim());
  if (missing.length) {
    throw new Error(`ROME_MAIL_PROVIDER=ses requires ${missing.join(", ")}`);
  }
  const address = (env.ROME_MAIL_ADDRESS as string).trim().toLowerCase();
  if (!/^[^\s@<>]+@[^\s@<>]+$/u.test(address))
    throw new Error("ROME_MAIL_ADDRESS is not an email address");
  return {
    address,
    guardianEmail: env.ROME_GUARDIAN_EMAIL?.trim().toLowerCase() || undefined,
    topicArn: (env.ROME_SES_TOPIC_ARN as string).trim(),
    bucket: (env.ROME_SES_BUCKET as string).trim(),
    region: (env.AWS_REGION as string).trim(),
  };
}

type AuthVerdictStatus = { status?: string };
export interface SesReceipt {
  spfVerdict?: AuthVerdictStatus;
  dkimVerdict?: AuthVerdictStatus;
  dmarcVerdict?: AuthVerdictStatus;
  spamVerdict?: AuthVerdictStatus;
  virusVerdict?: AuthVerdictStatus;
  action?: { type?: string; bucketName?: string; objectKey?: string };
}
export interface SesNotification {
  notificationType?: string;
  mail?: { messageId?: string; timestamp?: string };
  receipt?: SesReceipt;
}

const pass = (v?: AuthVerdictStatus) => v?.status === "PASS";
const failed = (v?: AuthVerdictStatus) => v?.status === "FAIL";

/** Trusted only when (DKIM or SPF) and DMARC and spam and virus all PASS; a virus FAIL blocks. */
export function sesAuthentication(receipt: SesReceipt = {}): MailAuthentication {
  return {
    authenticated:
      (pass(receipt.dkimVerdict) || pass(receipt.spfVerdict)) &&
      pass(receipt.dmarcVerdict) &&
      pass(receipt.spamVerdict) &&
      pass(receipt.virusVerdict),
    dmarc: pass(receipt.dmarcVerdict) ? "pass" : failed(receipt.dmarcVerdict) ? "fail" : "none",
    spam: failed(receipt.spamVerdict),
    blocked: failed(receipt.virusVerdict),
  };
}

interface StoredMessage {
  id: string;
  threadId: string;
  direction: "inbound" | "outbound";
  from?: EmailAddress[];
  to?: EmailAddress[];
  cc?: EmailAddress[];
  subject?: string;
  preview?: string;
  receivedAt: string;
  inReplyTo: string[];
  references: string[];
  attachments: EmailBodyPart[];
  authentication: MailAuthentication;
  labels: string[];
  /** Inbound raw MIME location; the body and attachments are re-read from here. */
  s3Key?: string;
  /** Outbound body, kept locally because SES keeps no sent copy. */
  body?: { text?: string; html?: string };
}

interface StoreData {
  inboundSecret: string;
  messages: Record<string, StoredMessage>;
}

// shortcut: one JSON file rewritten per message, capped at this many entries; move to the
// DB if mail volume ever makes this slow.
const MAX_STORED = 5000;

const bare = (id: string) => id.trim().replace(/^<|>$/gu, "");
const toList = (value: string | string[] | undefined): string[] =>
  (Array.isArray(value) ? value : value ? [value] : []).map(bare).filter(Boolean);
const flat = (a: AddressObject | AddressObject[] | undefined): EmailAddress[] =>
  (Array.isArray(a) ? a : a ? [a] : [])
    .flatMap((o) => o.value)
    .filter((v) => v.address)
    .map((v) => ({
      email: (v.address as string).toLowerCase(),
      ...(v.name ? { name: v.name } : {}),
    }));
const formatAddress = (a?: EmailAddress) =>
  a ? (a.name ? `${a.name} <${a.email}>` : a.email) : undefined;

function partsOf(parsed: ParsedMail): EmailBodyPart[] {
  return parsed.attachments.map((a, i) => ({
    partId: String(i),
    blobId: String(i),
    size: a.size,
    ...(a.filename ? { name: a.filename } : {}),
    type: a.contentType,
    ...(a.contentDisposition ? { disposition: a.contentDisposition } : {}),
    ...(a.cid ? { cid: bare(a.cid) } : {}),
  }));
}

/** Maps a parsed inbound message + SES receipt onto the payload Rome Cloud inbound uses. */
export function buildInboundEvent(
  notification: SesNotification,
  parsed: ParsedMail,
  config: Pick<SesMailConfig, "address">,
  threadIdOf: (refs: string[]) => string | undefined = () => undefined,
): { event: RomeMailEvent; record: StoredMessage } {
  const id =
    bare(parsed.messageId ?? "") || `${notification.mail?.messageId ?? randomUUID()}@ses-inbound`;
  const inReplyTo = toList(parsed.inReplyTo);
  const references = [...new Set([...toList(parsed.references), ...inReplyTo])];
  const threadId = threadIdOf(references) ?? references[0] ?? id;
  const authentication = sesAuthentication(notification.receipt);
  const attachments = partsOf(parsed);
  const receivedAt = notification.mail?.timestamp ?? new Date().toISOString();
  const preview = (parsed.text ?? "").replace(/\s+/gu, " ").trim().slice(0, 200);
  const labels = [
    "received",
    ...(authentication.authenticated ? [] : ["unauthenticated"]),
    ...(authentication.spam ? ["spam"] : []),
  ];
  const from = flat(parsed.from);
  const to = flat(parsed.to);
  const cc = flat(parsed.cc);
  const event: RomeMailEvent = {
    type: "message.received",
    provider: "ses",
    mailboxAddress: config.address,
    id,
    providerMessageId: id,
    threadId,
    from,
    to,
    cc,
    subject: parsed.subject,
    preview,
    ...(parsed.date ? { sentAt: parsed.date.toISOString() } : {}),
    receivedAt,
    hasAttachment: attachments.length > 0,
    attachments,
    authentication,
    labels,
  };
  const record: StoredMessage = {
    id,
    threadId,
    direction: "inbound",
    from,
    to,
    cc,
    subject: parsed.subject,
    preview,
    receivedAt,
    inReplyTo,
    references,
    attachments,
    authentication,
    labels,
  };
  return { event, record };
}

/** RFC 5322 message for SES Content.Raw. */
export async function buildOutboundMime(input: {
  from: string;
  to?: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  text?: string;
  html?: string;
  messageId: string;
  inReplyTo?: string;
  references?: string[];
}): Promise<Buffer> {
  const mail = new MailComposer({
    from: input.from,
    to: input.to,
    cc: input.cc,
    bcc: input.bcc,
    subject: input.subject,
    text: input.text,
    html: input.html,
    messageId: `<${input.messageId}>`,
    inReplyTo: input.inReplyTo ? `<${input.inReplyTo}>` : undefined,
    references: input.references?.map((r) => `<${r}>`),
  });
  return mail.compile().build();
}

interface Sender<C> {
  send(command: C): Promise<unknown>;
}
export interface SesMailDeps {
  ses?: Sender<SendEmailCommand>;
  s3?: Sender<GetObjectCommand>;
  /** Defaults to SNS signature verification against the real signing certificate. */
  verifySns?: (msg: SnsMessage) => Promise<void>;
  fetch?: typeof fetch;
  storePath?: string;
}

export type IngestInbound = (
  rawBody: string,
  signature: string,
) => Promise<{ status: string; reason?: string }>;

export class SesMailProvider implements MailProvider {
  private readonly ses: Sender<SendEmailCommand>;
  private readonly s3: Sender<GetObjectCommand>;
  private readonly verifySns: (msg: SnsMessage) => Promise<void>;
  private readonly fetchImpl: typeof fetch;
  private readonly storePath: string;
  private writes: Promise<unknown> = Promise.resolve();

  constructor(
    readonly config: SesMailConfig,
    deps: SesMailDeps = {},
  ) {
    // The SDK reads AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the environment.
    this.ses = deps.ses ?? new SESv2Client({ region: config.region });
    this.s3 = deps.s3 ?? new S3Client({ region: config.region });
    this.verifySns = deps.verifySns ?? ((msg) => verifySnsSignature(msg, config.region));
    this.fetchImpl = deps.fetch ?? globalThis.fetch;
    this.storePath = deps.storePath ?? join(getProfileDir(), "ses-mail.json");
  }

  private async load(): Promise<StoreData> {
    try {
      return JSON.parse(await readFile(this.storePath, "utf8")) as StoreData;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      return { inboundSecret: randomUUID() + randomUUID(), messages: {} };
    }
  }

  /** Serialized read-modify-write; returns what `fn` returns. */
  private update<T>(fn: (data: StoreData) => T): Promise<T> {
    const run = this.writes.then(async () => {
      const data = await this.load();
      const result = fn(data);
      const ids = Object.keys(data.messages);
      if (ids.length > MAX_STORED) {
        ids
          .sort((a, b) => data.messages[a].receivedAt.localeCompare(data.messages[b].receivedAt))
          .slice(0, ids.length - MAX_STORED)
          .forEach((id) => delete data.messages[id]);
      }
      await mkdir(dirname(this.storePath), { recursive: true });
      const tmp = `${this.storePath}.${process.pid}.tmp`;
      await writeFile(tmp, JSON.stringify(data), { mode: 0o600 });
      await rename(tmp, this.storePath);
      return result;
    });
    this.writes = run.catch(() => undefined);
    return run;
  }

  private async record(id: string): Promise<StoredMessage> {
    const found = (await this.load()).messages[id];
    if (!found) throw new MailProviderError(`message ${id} not found`, 404, "not_found");
    return found;
  }

  private async fetchRaw(s3Key: string): Promise<Buffer> {
    const out = (await this.s3.send(
      new GetObjectCommand({ Bucket: this.config.bucket, Key: s3Key }),
    )) as { Body?: { transformToByteArray(): Promise<Uint8Array> } };
    if (!out.Body) throw new MailProviderError(`empty S3 object ${s3Key}`, undefined, "s3_empty");
    return Buffer.from(await out.Body.transformToByteArray());
  }

  async provision(): Promise<ProvisionResult> {
    const inboundSecret = await this.update((d) => d.inboundSecret);
    return { address: this.config.address, inboundSecret };
  }

  async send(input: SendMailInput): Promise<SendMailResult> {
    const domain = this.config.address.split("@")[1];
    const id = `${randomUUID()}@${domain}`;
    let to = toList(input.to);
    let subject = input.subject?.trim() || "";
    let inReplyTo: string | undefined;
    let references: string[] = [];
    let threadId = id;
    if (input.inReplyToMessageId) {
      const parent = await this.record(bare(input.inReplyToMessageId));
      inReplyTo = parent.id;
      references = [...parent.references.filter((r) => r !== parent.id), parent.id];
      threadId = parent.threadId;
      const replyTo = parent.direction === "inbound" ? parent.from : parent.to;
      if (!to.length) to = (replyTo ?? []).map((a) => a.email);
      subject ||= /^re:/iu.test(parent.subject ?? "")
        ? (parent.subject as string)
        : `Re: ${parent.subject ?? ""}`.trim();
    }
    if (!to.length)
      throw new MailProviderError("no recipient for email", undefined, "no_recipient");
    const cc = input.cc ?? [];
    const bcc = input.bcc ?? [];
    const raw = await buildOutboundMime({
      from: this.config.address,
      to,
      cc,
      bcc,
      subject,
      text: input.text,
      html: input.html,
      messageId: id,
      inReplyTo,
      references,
    });
    try {
      await this.ses.send(
        new SendEmailCommand({
          FromEmailAddress: this.config.address,
          Destination: { ToAddresses: to, CcAddresses: cc, BccAddresses: bcc },
          Content: { Raw: { Data: raw } },
        }),
      );
    } catch (err) {
      const e = err as { name?: string; message?: string; $metadata?: { httpStatusCode?: number } };
      throw new MailProviderError(
        `SES send failed: ${e.message ?? String(err)}`,
        e.$metadata?.httpStatusCode,
        e.name,
      );
    }
    const toAddr = (list: string[]) => list.map((email) => ({ email }));
    await this.update((d) => {
      d.messages[id] = {
        id,
        threadId,
        direction: "outbound",
        from: [{ email: this.config.address }],
        to: toAddr(to),
        cc: toAddr(cc),
        subject,
        preview: (input.text ?? "").replace(/\s+/gu, " ").trim().slice(0, 200),
        receivedAt: new Date().toISOString(),
        inReplyTo: inReplyTo ? [inReplyTo] : [],
        references,
        attachments: [],
        authentication: { authenticated: true, spam: false, blocked: false },
        labels: ["sent"],
        body: { text: input.text, html: input.html },
      };
    }).catch((err: unknown) =>
      log.error("sent but could not record message", { id, error: String(err) }),
    );
    return { messageId: id, threadId };
  }

  async getMessage(messageId: string): Promise<RomeMailMessage> {
    const m = await this.record(bare(messageId));
    let body = m.body ?? {};
    if (m.s3Key) {
      const parsed = await simpleParser(await this.fetchRaw(m.s3Key));
      body = { text: parsed.text, html: parsed.html || undefined };
    }
    return {
      id: m.id,
      threadId: m.threadId,
      messageId: [m.id],
      inReplyTo: m.inReplyTo,
      references: m.references,
      from: m.from,
      to: m.to,
      cc: m.cc,
      subject: m.subject,
      preview: m.preview,
      receivedAt: m.receivedAt,
      body,
      attachments: m.attachments,
      hasAttachment: m.attachments.length > 0,
      provider: "ses",
      providerMessageId: m.id,
      mailboxAddress: this.config.address,
      direction: m.direction,
      authentication: m.authentication,
      labels: m.labels,
    };
  }

  // shortcut: the attachment travels as a data: URL (the adapter fetch()es downloadUrl), so it
  // is held in memory base64-encoded; switch to a presigned S3 URL if big attachments matter.
  async getAttachment(messageId: string, attachmentId: string): Promise<MailAttachmentDownload> {
    const m = await this.record(bare(messageId));
    if (!m.s3Key)
      throw new MailProviderError("message has no stored attachments", 404, "not_found");
    const att = (await simpleParser(await this.fetchRaw(m.s3Key))).attachments[
      Number(attachmentId)
    ];
    if (!att) throw new MailProviderError(`attachment ${attachmentId} not found`, 404, "not_found");
    return {
      downloadUrl: `data:${att.contentType};base64,${att.content.toString("base64")}`,
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      filename: att.filename,
      contentType: att.contentType,
      size: att.size,
    };
  }

  async listMessages(params: ListMessagesParams = {}): Promise<ListMessagesResult> {
    const sign = params.ascending ? 1 : -1;
    const all = Object.values((await this.load()).messages)
      .filter((m) => m.direction === "outbound" || m.authentication.authenticated)
      .filter(
        (m) =>
          (!params.after || m.receivedAt > params.after) &&
          (!params.before || m.receivedAt < params.before),
      )
      .sort((a, b) => sign * a.receivedAt.localeCompare(b.receivedAt));
    const start = Number(params.pageToken) || 0;
    const limit = params.limit ?? 50;
    const messages: RomeMailListItem[] = all.slice(start, start + limit).map((m) => ({
      providerMessageId: m.id,
      threadId: m.threadId,
      from: formatAddress(m.from?.[0]),
      subject: m.subject,
      preview: m.preview,
      receivedAt: m.receivedAt,
      labels: m.labels,
    }));
    return {
      messages,
      ...(start + limit < all.length ? { nextPageToken: String(start + limit) } : {}),
    };
  }

  /** Handles one SNS POST body. The status is for SNS: non-2xx makes it retry. */
  async handleSns(
    rawBody: string,
    ingest: IngestInbound,
  ): Promise<{ status: number; body: string }> {
    let msg: SnsMessage;
    try {
      msg = JSON.parse(rawBody) as SnsMessage;
      if (msg.TopicArn !== this.config.topicArn) throw new Error("unexpected TopicArn");
      await this.verifySns(msg);
    } catch (err) {
      log.warn("SNS message rejected", { error: err instanceof Error ? err.message : String(err) });
      return { status: 403, body: "forbidden" };
    }
    try {
      if (msg.Type === "SubscriptionConfirmation") {
        if (!isSnsUrl(msg.SubscribeURL, this.config.region))
          return { status: 403, body: "forbidden" };
        const res = await this.fetchImpl(msg.SubscribeURL as string, {
          signal: AbortSignal.timeout(10_000),
        });
        return { status: res.ok ? 200 : 502, body: "ok" };
      }
      if (msg.Type !== "Notification") return { status: 200, body: "ignored" };
      const notification = JSON.parse(msg.Message ?? "") as SesNotification;
      const action = notification.receipt?.action;
      if (notification.notificationType !== "Received" || action?.type !== "S3")
        return { status: 200, body: "ignored" };
      if (!action.objectKey || action.objectKey === "AMAZON_SES_SETUP_NOTIFICATION")
        return { status: 200, body: "ignored" };
      if (action.bucketName !== this.config.bucket) return { status: 403, body: "forbidden" };
      const parsed = await simpleParser(await this.fetchRaw(action.objectKey));
      const known = (await this.load()).messages;
      const { event, record } = buildInboundEvent(notification, parsed, this.config, (refs) =>
        refs.map((r) => known[r]?.threadId).find(Boolean),
      );
      record.s3Key = action.objectKey;
      const secret = await this.update((d) => {
        d.messages[record.id] ??= record;
        return d.inboundSecret;
      });
      const payload = JSON.stringify(event);
      const signature = createHmac("sha256", secret).update(payload).digest("hex");
      const result = await ingest(payload, signature);
      if (result.status === "dispatched" || result.reason === "duplicate")
        return { status: 200, body: "ok" };
      log.warn("inbound email not dispatched", { status: result.status, reason: result.reason });
      return { status: 503, body: "not dispatched" };
    } catch (err) {
      log.error("SES inbound handling failed", {
        error: err instanceof Error ? err.message : String(err),
      });
      return { status: 500, body: "error" };
    }
  }
}

function unconfigured(message: string): MailProvider {
  const fail = async (): Promise<never> => {
    throw new MailProviderError(message, undefined, "unconfigured");
  };
  return { provision: fail, send: fail, getMessage: fail, getAttachment: fail, listMessages: fail };
}

/** The SES mail setup when ROME_MAIL_PROVIDER=ses, else undefined (Rome Cloud mail stays). Bad
 *  env fails the email channel only: every provider call rejects with the missing variables. */
export function createSesMail(
  env: NodeJS.ProcessEnv = process.env,
): { provider: MailProvider; ses?: SesMailProvider; guardianEmail?: string } | undefined {
  if (env.ROME_MAIL_PROVIDER?.trim().toLowerCase() !== "ses") return undefined;
  try {
    const config = sesMailConfigFromEnv(env);
    const ses = new SesMailProvider(config);
    return { provider: ses, ses, guardianEmail: config.guardianEmail };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log.error(`email channel disabled: ${message}`);
    return { provider: unconfigured(message) };
  }
}
