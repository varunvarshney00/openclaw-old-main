// React/Frontend pe jab tu API call karta hai, toh Express.js ya Next.js mein ek Router hota hai (app.get('/chat'), app.post('/config')). Par WebSockets mein URL nahi badalte, sab kuch ek hi pipe se aata hai. Ye file tera WebSocket Router hai. Ye frontend ki "Method" (jaise method: "chat" ya method: "system.ping") ko padhta hai, aur usko backend ke specific code block (Handler) se jod deta hai. Saath hi, ye ensure karta hai ki kya user ki Aukaat (Role/Scope) hai wo method chalane ki?

import { formatControlPlaneActor, resolveControlPlaneActor } from "./control-plane-audit.js";
import { consumeControlPlaneWriteBudget } from "./control-plane-rate-limit.js";
import { ADMIN_SCOPE, authorizeOperatorScopesForMethod } from "./method-scopes.js";
import { ErrorCodes, errorShape } from "./protocol/index.js";
import { isRoleAuthorizedForMethod, parseGatewayRole } from "./role-policy.js";
import { agentHandlers } from "./server-methods/agent.js";
import { agentsHandlers } from "./server-methods/agents.js";
import { browserHandlers } from "./server-methods/browser.js";
import { channelsHandlers } from "./server-methods/channels.js";
import { chatHandlers } from "./server-methods/chat.js";
import { configHandlers } from "./server-methods/config.js";
import { connectHandlers } from "./server-methods/connect.js";
import { cronHandlers } from "./server-methods/cron.js";
import { deviceHandlers } from "./server-methods/devices.js";
import { doctorHandlers } from "./server-methods/doctor.js";
import { execApprovalsHandlers } from "./server-methods/exec-approvals.js";
import { healthHandlers } from "./server-methods/health.js";
import { logsHandlers } from "./server-methods/logs.js";
import { modelsHandlers } from "./server-methods/models.js";
import { nodeHandlers } from "./server-methods/nodes.js";
import { pushHandlers } from "./server-methods/push.js";
import { sendHandlers } from "./server-methods/send.js";
import { sessionsHandlers } from "./server-methods/sessions.js";
import { skillsHandlers } from "./server-methods/skills.js";
import { systemHandlers } from "./server-methods/system.js";
import { talkHandlers } from "./server-methods/talk.js";
import { toolsCatalogHandlers } from "./server-methods/tools-catalog.js";
import { ttsHandlers } from "./server-methods/tts.js";
import type { GatewayRequestHandlers, GatewayRequestOptions } from "./server-methods/types.js";
import { updateHandlers } from "./server-methods/update.js";
import { usageHandlers } from "./server-methods/usage.js";
import { voicewakeHandlers } from "./server-methods/voicewake.js";
import { webHandlers } from "./server-methods/web.js";
import { wizardHandlers } from "./server-methods/wizard.js";

// Pichli files mein humne user se password manga aur verify kiya. Usko bolte hain Authentication (Pehchan - "Tum kaun ho?").
// Lekin ye function karta hai Authorization (Aukaat - "Tumhari permission kya hai?").
// Maan le ek employee company mein ghus gaya (Authenticated), par kya wo aam employee bank ke locker room mein ja sakta hai? Nahi! Ye function wahi check karta hai ki kya is user ke paas is specific kaam (method) ko karne ki permission hai ya nahi.

// KYA HAI: Ye teen commands system ke sabse khatarnak methods hain. Ye server ki config badal sakte hain ya system ko update kar sakte hain.
// KYU HAI: Inko ek alag list (Set) mein rakha gaya hai kyunki pichli file mein tune dekha tha, in commands par ek strict "Rate Limiter" (Budget) lagta hai taaki koi admin account hack hone par bhi inko lagatar spam na kar sake.
const CONTROL_PLANE_WRITE_METHODS = new Set(["config.apply", "config.patch", "update.run"]);

// KYA HAI: 1. !client?.connect: Agar user ka connection data hi nahi hai (jaise shuruwaati connection ke time), toh auth bypass kar do (baad mein pakdenge).
// 2. method === "health": "Health" ek public endpoint hota hai. Load balancers (jaise AWS/Nginx) har 10 second mein puchte hain "Bhai zinda ho?". Is chote se sawaal ke liye unse identity card/password mangna bevakoofi hai. Isliye isko seedha return null (Green Signal) de diya.
function authorizeGatewayMethod(method: string, client: GatewayRequestOptions["client"]) {
  // If: There is no client Or client has no connect data Then: Allow the request.
  if (!client?.connect) {
    return null;
    // Note: Dhyan rakhna, is function mein return null ka matlab hai "Koi error nahi hai, tum aage jaa sakte ho." (Green Signal).
  }
  if (method === "health") {
    return null;
    // Note: Dhyan rakhna, is function mein return null ka matlab hai "Koi error nahi hai, tum aage jaa sakte ho." (Green Signal).
  }

  const roleRaw = client.connect.role ?? "operator";
  console.log("role raw--------->", roleRaw);

  const role = parseGatewayRole(roleRaw);
  console.log("parsed role raw----->", role);

  if (!role) {
    return errorShape(ErrorCodes.INVALID_REQUEST, `unauthorized role: ${roleRaw}`);
  }

  const scopes = client.connect.scopes ?? [];
  console.log("scopes---->", scopes);

  if (!isRoleAuthorizedForMethod(role, method)) {
    return errorShape(ErrorCodes.INVALID_REQUEST, `unauthorized role: ${role}`);
  }

  if (role === "node") {
    return null;
  }

  if (scopes.includes(ADMIN_SCOPE)) {
    return null;
  }

  const scopeAuth = authorizeOperatorScopesForMethod(method, scopes);
  
  if (!scopeAuth.allowed) {
    return errorShape(ErrorCodes.INVALID_REQUEST, `missing scope: ${scopeAuth.missingScope}`);
  }
  
  return null;
}

export const coreGatewayHandlers: GatewayRequestHandlers = {
  ...connectHandlers,
  ...logsHandlers,
  ...voicewakeHandlers,
  ...healthHandlers,
  ...channelsHandlers,
  ...chatHandlers,
  ...cronHandlers,
  ...deviceHandlers,
  ...doctorHandlers,
  ...execApprovalsHandlers,
  ...webHandlers,
  ...modelsHandlers,
  ...configHandlers,
  ...wizardHandlers,
  ...talkHandlers,
  ...toolsCatalogHandlers,
  ...ttsHandlers,
  ...skillsHandlers,
  ...sessionsHandlers,
  ...systemHandlers,
  ...updateHandlers,
  ...nodeHandlers,
  ...pushHandlers,
  ...sendHandlers,
  ...usageHandlers,
  ...agentHandlers,
  ...agentsHandlers,
  ...browserHandlers,
};

export async function handleGatewayRequest(
  opts: GatewayRequestOptions & { extraHandlers?: GatewayRequestHandlers },
): Promise<void> {
  const { req, respond, client, isWebchatConnect, context } = opts;
  const authError = authorizeGatewayMethod(req.method, client);
  if (authError) {
    respond(false, undefined, authError);
    return;
  }
  if (CONTROL_PLANE_WRITE_METHODS.has(req.method)) {
    const budget = consumeControlPlaneWriteBudget({ client });
    if (!budget.allowed) {
      const actor = resolveControlPlaneActor(client);
      context.logGateway.warn(
        `control-plane write rate-limited method=${req.method} ${formatControlPlaneActor(actor)} retryAfterMs=${budget.retryAfterMs} key=${budget.key}`,
      );
      respond(
        false,
        undefined,
        errorShape(
          ErrorCodes.UNAVAILABLE,
          `rate limit exceeded for ${req.method}; retry after ${Math.ceil(budget.retryAfterMs / 1000)}s`,
          {
            retryable: true,
            retryAfterMs: budget.retryAfterMs,
            details: {
              method: req.method,
              limit: "3 per 60s",
            },
          },
        ),
      );
      return;
    }
  }
  const handler = opts.extraHandlers?.[req.method] ?? coreGatewayHandlers[req.method];
  if (!handler) {
    respond(
      false,
      undefined,
      errorShape(ErrorCodes.INVALID_REQUEST, `unknown method: ${req.method}`),
    );
    return;
  }
  await handler({
    req,
    params: (req.params ?? {}) as Record<string, unknown>,
    client,
    isWebchatConnect,
    respond,
    context,
  });
}
