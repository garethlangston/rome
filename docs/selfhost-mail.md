# Self-host mail over Amazon SES

Fork-only. Replaces Rome Cloud mail for the email channel with Amazon SES. Two parts:

- **Core provider** (`packages/core/src/selfhost/ses-mail.ts`, one hook line in `packages/core/src/index.ts`): sends raw MIME through SESv2, reads message bodies and attachments from S3, keeps every message in `<profile>/ses-mail.json`.
- **`ses-mail` app** (custom app, not in this repo): the public SNS endpoint for inbound mail.

The AWS SDK, `mailparser` and `nodemailer` dependencies are not in `package.json`. `.github/workflows/selfhost-image.yml` adds them to `packages/core` (`--lockfile-only`) before the Docker build.

## Environment

Set these on the Rome container. The core provider and the `ses-mail` app both read them.

| Variable | Meaning |
|---|---|
| `ROME_MAIL_PROVIDER=ses` | Turns SES on. Unset keeps Rome Cloud mail. |
| `ROME_MAIL_ADDRESS` | The channel's own address, e.g. `computer@example.com`. |
| `ROME_SES_TOPIC_ARN` | The SNS topic SES notifies. Inbound requests for any other topic get 403. |
| `ROME_SES_BUCKET` | The S3 bucket the SES receipt rule writes raw mail to. |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` | Credentials with `ses:SendEmail` and `s3:GetObject` on the bucket. |
| `ROME_GUARDIAN_EMAIL` | Fresh installs only: the guardian's address. Or set it in the dashboard. An existing install already stores it. |

A missing variable disables only the email channel; every provider call fails naming the missing variables.

## AWS setup

1. Verify the domain and the address in SES (DKIM, SPF, DMARC) and get out of the sandbox.
2. Create the S3 bucket and an SNS topic in the same region.
3. SES receipt rule for the address: action S3 (the bucket), and the SNS topic notification.
4. Subscribe `https://<your-host>/api/mail/ses/inbound` (HTTPS) to the topic. The `ses-mail` app confirms the subscription itself.

## Caddy rewrite

AWS keeps posting to the old URL. The reverse proxy in front of Rome rewrites it to the app's public path:

```
rewrite /api/mail/ses/inbound /api/app-api/ses-mail/sns
```

Put it in the site block before `reverse_proxy`.

## The `ses-mail` app

`POST /api/app-api/ses-mail/sns` (declared `api.noAuth: [/sns]`). For each request it:

1. checks `TopicArn` and the SNS signature (and only follows a `SubscribeURL` on the regional SNS host);
2. reads the raw mail from S3 and parses it, looking up the thread through In-Reply-To then References (including SES's replacement Message-ID aliases);
3. writes the message record to `<profile>/ses-mail-inbound/<sha256(id)>.json`;
4. calls the `email_inbound` system action with the event and an HMAC signed with `inboundSecret` from `ses-mail.json`.

Answers 200 when dispatched or duplicate, 503 when not dispatched or the channel has not provisioned its secret yet, 500 on errors, 403 when verification fails; SNS retries any non-2xx.

The app never writes `ses-mail.json`. The core provider folds the drop files into it (on `getMessage` and `listMessages`), so only one process writes the store.
