import { Hono } from "hono";
import type { ApiDeps } from "../deps.js";

/** Public SNS webhook for SES inbound mail. Unauthenticated by design: the SNS signature,
 *  TopicArn and bucket checks in `SesMailProvider.handleSns` are the credential. */
export function sesInboundRoutes(deps: Pick<ApiDeps, "sesMailInbound">): Hono {
  const app = new Hono();
  app.post("/mail/ses/inbound", async (c) => {
    if (!deps.sesMailInbound) return c.text("not found", 404);
    const { status, body } = await deps.sesMailInbound(await c.req.text());
    return c.text(body, status as 200);
  });
  return app;
}
