import { execFileSync } from "node:child_process";
import { createSign } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it, rs } from "@rstest/core";
import { simpleParser } from "mailparser";
import { RomeCloudMailProvider } from "./rome-cloud-mail.js";
import {
  SesMailProvider,
  buildInboundEvent,
  buildOutboundMime,
  createSesMail,
  sesAuthentication,
} from "./ses-mail.js";
import { type SnsMessage, verifySnsSignature } from "./sns-verify.js";

const REGION = "eu-west-2";
const TOPIC = "arn:aws:sns:eu-west-2:123456789012:rome-inbound";
const CERT_URL = `https://sns.${REGION}.amazonaws.com/SimpleNotificationService-test.pem`;
let certPem = "";
let keyPem = "";

beforeAll(() => {
  const dir = mkdtempSync(join(tmpdir(), "sns-test-"));
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-subj",
      "/CN=sns-test",
      "-days",
      "2",
      "-keyout",
      join(dir, "k.pem"),
      "-out",
      join(dir, "c.pem"),
    ],
    { stdio: "ignore" },
  );
  certPem = readFileSync(join(dir, "c.pem"), "utf8");
  keyPem = readFileSync(join(dir, "k.pem"), "utf8");
});

function signed(fields: Partial<SnsMessage>, version = "1"): SnsMessage {
  const msg: SnsMessage = {
    Type: "Notification",
    MessageId: "m-1",
    TopicArn: TOPIC,
    Message: "{}",
    Timestamp: "2026-01-01T00:00:00.000Z",
    SignatureVersion: version,
    SigningCertURL: CERT_URL,
    ...fields,
  };
  const keys = ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"];
  const toSign = keys
    .filter((k) => k !== "Subject" || msg.Subject !== undefined)
    .map((k) => `${k}\n${msg[k as keyof SnsMessage]}\n`)
    .join("");
  msg.Signature = createSign(version === "1" ? "SHA1" : "SHA256")
    .update(toSign)
    .sign(keyPem, "base64");
  return msg;
}

describe("verifySnsSignature", () => {
  const cert = async () => certPem;
  it("accepts valid v1 and v2 signatures", async () => {
    await expect(verifySnsSignature(signed({}), REGION, cert)).resolves.toBeUndefined();
    await expect(
      verifySnsSignature(signed({ Subject: "s" }, "2"), REGION, cert),
    ).resolves.toBeUndefined();
  });
  it("rejects a tampered message", async () => {
    const msg = { ...signed({}), Message: '{"x":1}' };
    await expect(verifySnsSignature(msg, REGION, cert)).rejects.toThrow("mismatch");
  });
  it("rejects a certificate host that is not the regional SNS host", async () => {
    for (const url of [
      "https://evil.example.com/x.pem",
      `http://sns.${REGION}.amazonaws.com/x.pem`,
      `https://sns.${REGION}.amazonaws.com.evil.com/x.pem`,
      `https://sns.us-east-1.amazonaws.com/x.pem`,
      `https://sns.${REGION}.amazonaws.com/x.txt`,
    ]) {
      const getCert = rs.fn(cert);
      await expect(
        verifySnsSignature(signed({ SigningCertURL: url }), REGION, getCert),
      ).rejects.toThrow("SigningCertURL");
      expect(getCert).not.toHaveBeenCalled();
    }
  });
});

const baseEnv = {
  ROME_MAIL_PROVIDER: "ses",
  ROME_MAIL_ADDRESS: "computer@gareths.cloud",
  ROME_SES_TOPIC_ARN: TOPIC,
  ROME_SES_BUCKET: "bucket",
  AWS_ACCESS_KEY_ID: "id",
  AWS_SECRET_ACCESS_KEY: "secret",
  AWS_REGION: REGION,
};

const rawMime = (extra = "") =>
  Buffer.from(
    `From: Gareth <gareth@gmail.com>\r\nTo: computer@gareths.cloud\r\nSubject: Hello\r\nMessage-ID: <abc@mail.gmail.com>\r\nDate: Thu, 01 Jan 2026 00:00:00 +0000\r\n${extra}Content-Type: text/plain\r\n\r\nhi there\r\n`,
  );
const receipt = (o: Record<string, string> = {}) => ({
  action: { type: "S3", bucketName: "bucket", objectKey: "k1" },
  spfVerdict: { status: o.spf ?? "PASS" },
  dkimVerdict: { status: o.dkim ?? "PASS" },
  dmarcVerdict: { status: o.dmarc ?? "PASS" },
  spamVerdict: { status: o.spam ?? "PASS" },
  virusVerdict: { status: o.virus ?? "PASS" },
});

describe("provider selection", () => {
  it("is Rome Cloud when ROME_MAIL_PROVIDER is unset", () => {
    expect(createSesMail({})).toBeUndefined();
    expect(new RomeCloudMailProvider()).toBeDefined();
  });
  it("is SES when configured", () => {
    expect(createSesMail(baseEnv)?.provider).toBeInstanceOf(SesMailProvider);
  });
  it("fails only the email provider calls when env is missing", async () => {
    const sel = createSesMail({ ROME_MAIL_PROVIDER: "ses" });
    await expect(sel?.provider.provision()).rejects.toThrow("ROME_SES_BUCKET");
  });
});

describe("SES notification mapping", () => {
  it("maps verdicts to authentication", () => {
    expect(sesAuthentication(receipt()).authenticated).toBe(true);
    expect(sesAuthentication(receipt({ dkim: "FAIL" })).authenticated).toBe(true); // SPF passes
    expect(sesAuthentication(receipt({ dkim: "FAIL", spf: "FAIL" })).authenticated).toBe(false);
    expect(sesAuthentication(receipt({ dmarc: "FAIL" }))).toMatchObject({
      authenticated: false,
      dmarc: "fail",
    });
    expect(sesAuthentication(receipt({ spam: "FAIL" }))).toMatchObject({
      authenticated: false,
      spam: true,
    });
    expect(sesAuthentication(receipt({ virus: "FAIL" }))).toMatchObject({
      authenticated: false,
      blocked: true,
    });
  });
  it("builds the inbound payload", async () => {
    const parsed = await simpleParser(rawMime("In-Reply-To: <out1@gareths.cloud>\r\n"));
    const { event } = buildInboundEvent(
      { receipt: receipt(), mail: { timestamp: "2026-01-01T00:00:01Z" } },
      parsed,
      {
        address: "computer@gareths.cloud",
      },
    );
    expect(event).toMatchObject({
      type: "message.received",
      providerMessageId: "abc@mail.gmail.com",
      threadId: "out1@gareths.cloud",
      from: [{ email: "gareth@gmail.com", name: "Gareth" }],
      subject: "Hello",
      preview: "hi there",
      authentication: { authenticated: true, dmarc: "pass", spam: false, blocked: false },
    });
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

describe("SesMailProvider.handleSns", () => {
  function setup(verifySns = async () => {}) {
    const sent: unknown[] = [];
    const fetchSpy = rs.fn(async () => new Response("ok"));
    const ses = new SesMailProvider(createConfig(), {
      ses: { send: async (c) => void sent.push(c.input) },
      s3: { send: async () => ({ Body: { transformToByteArray: async () => rawMime() } }) },
      verifySns,
      fetch: fetchSpy as unknown as typeof fetch,
      storePath: join(mkdtempSync(join(tmpdir(), "ses-store-")), "s.json"),
    });
    return { ses, sent, fetchSpy };
  }
  function createConfig() {
    return { address: "computer@gareths.cloud", topicArn: TOPIC, bucket: "bucket", region: REGION };
  }
  const note = (message: unknown, extra: Partial<SnsMessage> = {}) =>
    JSON.stringify({
      Type: "Notification",
      TopicArn: TOPIC,
      Message: JSON.stringify(message),
      ...extra,
    });
  const received = {
    notificationType: "Received",
    mail: { messageId: "sesid" },
    receipt: receipt(),
  };

  it("rejects a wrong TopicArn and a failed signature", async () => {
    const ingest = rs.fn(async () => ({ status: "dispatched" }));
    expect(
      (await setup().ses.handleSns(note(received, { TopicArn: "arn:other" }), ingest)).status,
    ).toBe(403);
    const bad = setup(async () => {
      throw new Error("no");
    });
    expect((await bad.ses.handleSns(note(received), ingest)).status).toBe(403);
    expect(ingest).not.toHaveBeenCalled();
  });

  it("only follows a SubscribeURL on the regional SNS host", async () => {
    const { ses, fetchSpy } = setup();
    const confirm = (url: string) =>
      JSON.stringify({ Type: "SubscriptionConfirmation", TopicArn: TOPIC, SubscribeURL: url });
    const ingest = rs.fn(async () => ({ status: "dispatched" }));
    expect(
      (await ses.handleSns(confirm("https://evil.example.com/?Action=ConfirmSubscription"), ingest))
        .status,
    ).toBe(403);
    expect(fetchSpy).not.toHaveBeenCalled();
    const ok = confirm(`https://sns.${REGION}.amazonaws.com/?Action=ConfirmSubscription&Token=t`);
    expect((await ses.handleSns(ok, ingest)).status).toBe(200);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("ingests a signed payload, ignores the setup notification, and replies with threading", async () => {
    const { ses, sent } = setup();
    const ingest = rs.fn(async () => ({ status: "dispatched" }));
    const setupNote = {
      ...received,
      receipt: {
        ...receipt(),
        action: { type: "S3", bucketName: "bucket", objectKey: "AMAZON_SES_SETUP_NOTIFICATION" },
      },
    };
    expect((await ses.handleSns(note(setupNote), ingest)).body).toBe("ignored");
    expect(ingest).not.toHaveBeenCalled();

    expect((await ses.handleSns(note(received), ingest)).status).toBe(200);
    const [payload, signature] = ingest.mock.calls[0] as unknown as [string, string];
    expect(JSON.parse(payload).authentication.authenticated).toBe(true);
    const { inboundSecret } = await ses.provision();
    const { createHmac } = await import("node:crypto");
    expect(signature).toBe(createHmac("sha256", inboundSecret).update(payload).digest("hex"));

    const msg = await ses.getMessage("abc@mail.gmail.com");
    expect(msg.body.text).toContain("hi there");
    const result = await ses.send({ inReplyToMessageId: "abc@mail.gmail.com", text: "yo" });
    expect(result.threadId).toBe("abc@mail.gmail.com");
    const raw = Buffer.from(
      (sent[0] as { Content: { Raw: { Data: Uint8Array } } }).Content.Raw.Data,
    );
    const parsed = await simpleParser(raw);
    expect(parsed.to).toMatchObject({ text: "gareth@gmail.com" });
    expect(parsed.subject).toBe("Re: Hello");
    expect(parsed.inReplyTo).toBe("<abc@mail.gmail.com>");
    expect((await ses.listMessages()).messages.map((m) => m.providerMessageId)).toContain(
      result.messageId,
    );
  });
});
