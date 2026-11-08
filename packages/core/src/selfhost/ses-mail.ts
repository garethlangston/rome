import { randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";
import { simpleParser } from "mailparser";
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
  type RomeMailListItem,
  type RomeMailMessage,
  type SendMailInput,
  type SendMailResult,
} from "../lib/rome-cloud-mail.js";

const log = createLogger("ses-mail");

// Amazon SES mail provider: outbound via SESv2 SendEmail (raw MIME), message bodies from S3.
// Inbound arrives through the `ses-mail` app, which drops each record in DROP_DIR for this
// provider to fold into the store. Selected by ROME_MAIL_PROVIDER=ses. See docs/selfhost-mail.md.

export interface SesMailConfig {
  address: string;
  bucket: string;
  region: string;
}

const REQUIRED_ENV = [
  "ROME_MAIL_ADDRESS",
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
    bucket: (env.ROME_SES_BUCKET as string).trim(),
    region: (env.AWS_REGION as string).trim(),
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
  /** SES's own Message-ID (`<id>@<region>.amazonses.com`) -> our outbound record id. SES
   *  replaces the Message-ID we set, so replies cite the SES one. Absent in older stores. */
  aliases: Record<string, string>;
}

/** Where the `ses-mail` app drops inbound records (one JSON file each). The app is a separate
 *  process, so only this provider ever writes the store; it folds the drops in. */
export const dropDirOf = (storePath: string) => join(dirname(storePath), "ses-mail-inbound");

// shortcut: one JSON file rewritten per message, capped at this many entries; move to the
// DB if mail volume ever makes this slow.
const MAX_STORED = 5000;

const bare = (id: string) => id.trim().replace(/^<|>$/gu, "");
const toList = (value: string | string[] | undefined): string[] =>
  (Array.isArray(value) ? value : value ? [value] : []).map(bare).filter(Boolean);
const formatAddress = (a?: EmailAddress) =>
  a ? (a.name ? `${a.name} <${a.email}>` : a.email) : undefined;

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
  storePath?: string;
}

export class SesMailProvider implements MailProvider {
  private readonly ses: Sender<SendEmailCommand>;
  private readonly s3: Sender<GetObjectCommand>;
  private readonly storePath: string;
  private readonly dropDir: string;
  private writes: Promise<unknown> = Promise.resolve();

  constructor(
    readonly config: SesMailConfig,
    deps: SesMailDeps = {},
  ) {
    // The SDK reads AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the environment.
    this.ses = deps.ses ?? new SESv2Client({ region: config.region });
    this.s3 = deps.s3 ?? new S3Client({ region: config.region });
    this.storePath = deps.storePath ?? join(getProfileDir(), "ses-mail.json");
    this.dropDir = dropDirOf(this.storePath);
  }

  /** Folds the app's inbound drops into the store, then deletes them. Idempotent: a crash
   *  between the write and the unlink only repeats the `??=`. Unreadable drops are skipped. */
  private async foldInbound(): Promise<void> {
    const names = (await readdir(this.dropDir).catch(() => [])).filter((n) => n.endsWith(".json"));
    if (!names.length) return;
    const records: StoredMessage[] = [];
    const done: string[] = [];
    for (const name of names) {
      try {
        const rec = JSON.parse(await readFile(join(this.dropDir, name), "utf8")) as StoredMessage;
        if (typeof rec.id === "string" && rec.id) records.push(rec);
        done.push(name);
      } catch (err) {
        log.warn("skipping unreadable inbound drop", { name, error: String(err) });
      }
    }
    await this.update((d) => {
      for (const rec of records) d.messages[rec.id] ??= rec;
    });
    await Promise.all(done.map((n) => unlink(join(this.dropDir, n)).catch(() => undefined)));
  }

  private async load(): Promise<StoreData> {
    try {
      const data = JSON.parse(await readFile(this.storePath, "utf8")) as StoreData;
      data.aliases ??= {};
      return data;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      return { inboundSecret: randomUUID() + randomUUID(), messages: {}, aliases: {} };
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
    await this.foldInbound();
    const data = await this.load();
    const found = data.messages[data.aliases[id] ?? id];
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
    let sesMessageId: string | undefined;
    try {
      const out = (await this.ses.send(
        new SendEmailCommand({
          FromEmailAddress: this.config.address,
          Destination: { ToAddresses: to, CcAddresses: cc, BccAddresses: bcc },
          Content: { Raw: { Data: raw } },
        }),
      )) as { MessageId?: string } | undefined;
      sesMessageId = out?.MessageId;
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
      if (sesMessageId) d.aliases[`${sesMessageId}@${this.config.region}.amazonses.com`] = id;
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
    await this.foldInbound();
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
}

function unconfigured(message: string): MailProvider {
  const fail = async (): Promise<never> => {
    throw new MailProviderError(message, undefined, "unconfigured");
  };
  return { provision: fail, send: fail, getMessage: fail, getAttachment: fail, listMessages: fail };
}

/** The SES provider when ROME_MAIL_PROVIDER=ses, else undefined (Rome Cloud mail stays). Bad
 *  env fails the email channel only: every provider call rejects with the missing variables. */
export function selfhostMailProvider(
  env: NodeJS.ProcessEnv = process.env,
): MailProvider | undefined {
  if (env.ROME_MAIL_PROVIDER?.trim().toLowerCase() !== "ses") return undefined;
  try {
    return new SesMailProvider(sesMailConfigFromEnv(env));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log.error(`email channel disabled: ${message}`);
    return unconfigured(message);
  }
}
