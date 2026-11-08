import { mkdirSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "@rstest/core";
import { simpleParser } from "mailparser";
import { RomeCloudMailProvider } from "../lib/rome-cloud-mail.js";
import { SesMailProvider, buildOutboundMime, dropDirOf, selfhostMailProvider } from "./ses-mail.js";

const REGION = "eu-west-2";
const SES_ID = "010b01a1b2243b0d-aaaa-bbbb-cccc-000000";
const SES_ALIAS = `${SES_ID}@${REGION}.amazonses.com`;

const baseEnv = {
  ROME_MAIL_PROVIDER: "ses",
  ROME_MAIL_ADDRESS: "computer@gareths.cloud",
  ROME_SES_BUCKET: "bucket",
  AWS_ACCESS_KEY_ID: "id",
  AWS_SECRET_ACCESS_KEY: "secret",
  AWS_REGION: REGION,
};

const rawMime = Buffer.from(
  "From: Gareth <gareth@gmail.com>\r\nTo: computer@gareths.cloud\r\nSubject: Hello\r\nMessage-ID: <abc@mail.gmail.com>\r\nDate: Thu, 01 Jan 2026 00:00:00 +0000\r\nContent-Type: text/plain\r\n\r\nhi there\r\n",
);

function setup() {
  const sent: unknown[] = [];
  const storePath = join(mkdtempSync(join(tmpdir(), "ses-store-")), "s.json");
  const ses = new SesMailProvider(
    { address: "computer@gareths.cloud", bucket: "bucket", region: REGION },
    {
      ses: {
        send: async (c) => {
          sent.push(c.input);
          return { MessageId: SES_ID };
        },
      },
      s3: { send: async () => ({ Body: { transformToByteArray: async () => rawMime } }) },
      storePath,
    },
  );
  const drop = (name: string, record: unknown) => {
    mkdirSync(dropDirOf(storePath), { recursive: true });
    writeFileSync(join(dropDirOf(storePath), name), JSON.stringify(record));
  };
  return { ses, sent, storePath, drop };
}

const inboundRecord = {
  id: "abc@mail.gmail.com",
  threadId: "abc@mail.gmail.com",
  direction: "inbound",
  from: [{ email: "gareth@gmail.com", name: "Gareth" }],
  to: [{ email: "computer@gareths.cloud" }],
  subject: "Hello",
  preview: "hi there",
  receivedAt: "2026-01-01T00:00:01Z",
  inReplyTo: [],
  references: [],
  attachments: [],
  authentication: { authenticated: true, spam: false, blocked: false },
  labels: ["received"],
  s3Key: "k1",
};

describe("provider selection", () => {
  it("is Rome Cloud when ROME_MAIL_PROVIDER is unset", () => {
    expect(selfhostMailProvider({})).toBeUndefined();
    expect(new RomeCloudMailProvider()).toBeDefined();
  });
  it("is SES when configured", () => {
    expect(selfhostMailProvider(baseEnv)).toBeInstanceOf(SesMailProvider);
  });
  it("fails only the email provider calls when env is missing", async () => {
    await expect(selfhostMailProvider({ ROME_MAIL_PROVIDER: "ses" })?.provision()).rejects.toThrow(
      "ROME_SES_BUCKET",
    );
  });
});

describe("outbound MIME", () => {
  it("carries Message-ID, In-Reply-To and References", async () => {
    const raw = await buildOutboundMime({
      from: "computer@gareths.cloud",
      to: ["gareth@gmail.com"],
      bcc: ["hidden@example.com"],
      subject: "Re: Hello",
      text: "t",
      html: "<p>t</p>",
      messageId: "new@gareths.cloud",
      inReplyTo: "abc@mail.gmail.com",
      references: ["root@x", "abc@mail.gmail.com"],
    });
    const parsed = await simpleParser(raw);
    expect(parsed.messageId).toBe("<new@gareths.cloud>");
    expect(parsed.inReplyTo).toBe("<abc@mail.gmail.com>");
    expect(parsed.references).toEqual(["<root@x>", "<abc@mail.gmail.com>"]);
    expect(parsed.html).toContain("<p>t</p>");
    expect(raw.toString()).not.toContain("hidden@example.com");
  });
});

describe("inbound drops from the ses-mail app", () => {
  it("folds a dropped record into the store, reads its body, replies in thread, deletes the drop", async () => {
    const { ses, sent, storePath, drop } = setup();
    drop("a.json", inboundRecord);
    drop("bad.json", "not a record"); // skipped, not fatal
    const msg = await ses.getMessage("abc@mail.gmail.com");
    expect(msg.body.text).toContain("hi there");
    expect(readdirSync(dropDirOf(storePath)).filter((n) => n !== "bad.json")).toEqual([]);
    const result = await ses.send({ inReplyToMessageId: "abc@mail.gmail.com", text: "yo" });
    expect(result.threadId).toBe("abc@mail.gmail.com");
    const parsed = await simpleParser(
      Buffer.from((sent[0] as { Content: { Raw: { Data: Uint8Array } } }).Content.Raw.Data),
    );
    expect(parsed.to).toMatchObject({ text: "gareth@gmail.com" });
    expect(parsed.subject).toBe("Re: Hello");
    expect(parsed.inReplyTo).toBe("<abc@mail.gmail.com>");
    expect((await ses.listMessages()).messages.map((m) => m.providerMessageId)).toContain(
      result.messageId,
    );
  });

  it("lists a drop that no getMessage has folded yet, and never overwrites a stored record", async () => {
    const { ses, drop } = setup();
    drop("a.json", inboundRecord);
    expect((await ses.listMessages()).messages).toHaveLength(1);
    drop("a.json", { ...inboundRecord, subject: "changed" });
    expect((await ses.getMessage("abc@mail.gmail.com")).subject).toBe("Hello");
  });
});

describe("SES Message-ID alias", () => {
  it("stores the alias from the SES MessageId and resolves it", async () => {
    const { ses } = setup();
    const sent = await ses.send({ to: "gareth@gmail.com", subject: "Hi", text: "yo" });
    expect((await ses.getMessage(SES_ALIAS)).id).toBe(sent.messageId);
  });

  it("loads an older store without aliases", async () => {
    const { ses, storePath } = setup();
    writeFileSync(storePath, JSON.stringify({ inboundSecret: "s", messages: {} }));
    await expect(ses.provision()).resolves.toMatchObject({ inboundSecret: "s" });
  });
});
