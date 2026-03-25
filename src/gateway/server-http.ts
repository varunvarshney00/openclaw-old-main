// ye hmare poore backend ka "Grand Central Station" ya "Main API Gateway" hai.

// Jab bhi bahar ki duniya se, jaise (WhatsApp, Slack, Web UI, ya OpenAI) koi bhi request hmare server par aati hai, toh wo sabse pehle is file ke gate par knock krti hai.



// OpenClaw ne yahan Express.js ya Fastify jaisa koi external third-party framework use nahi kiya hai. 
// Usne Node.js ke ekdum core, in-built module node:http ka use kiya hai. 
// Yeh dikhata hai ki codebase ekdum raw aur fast performance ke liye design hua hai.
import {

  // Yeh woh actual function hai jo server start karega (port 3000 ya 8080 par sun-na shuru karega).
  // "as" ka mtlb hota h, Developer ne isko rename karke createHttpServer kar diya.
  createServer as createHttpServer,
  type Server as HttpServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";


import { createServer as createHttpsServer } from "node:https";

import type { TlsOptions } from "node:tls";

import type { WebSocketServer } from "ws";

import { resolveAgentAvatar } from "../agents/identity-avatar.js";

import {
  A2UI_PATH,
  CANVAS_HOST_PATH,
  CANVAS_WS_PATH,
  handleA2uiHttpRequest,
} from "../canvas-host/a2ui.js";

import type { CanvasHostHandler } from "../canvas-host/server.js";

import { loadConfig } from "../config/config.js";

import type { createSubsystemLogger } from "../logging/subsystem.js";

import { safeEqualSecret } from "../security/secret-equal.js";

import { handleSlackHttpRequest } from "../slack/http/index.js";

import {
  AUTH_RATE_LIMIT_SCOPE_HOOK_AUTH,
  createAuthRateLimiter,
  normalizeRateLimitClientIp,
  type AuthRateLimiter,
} from "./auth-rate-limit.js";

import {
  authorizeHttpGatewayConnect,
  isLocalDirectRequest,
  type GatewayAuthResult,
  type ResolvedGatewayAuth,
} from "./auth.js";

import { CANVAS_CAPABILITY_TTL_MS, normalizeCanvasScopedUrl } from "./canvas-capability.js";

import {
  handleControlUiAvatarRequest,
  handleControlUiHttpRequest,
  type ControlUiRootState,
} from "./control-ui.js";

import { applyHookMappings } from "./hooks-mapping.js";

import {
  extractHookToken,
  getHookAgentPolicyError,
  getHookChannelError,
  type HookAgentDispatchPayload,
  type HooksConfigResolved,
  isHookAgentAllowed,
  normalizeAgentPayload,
  normalizeHookHeaders,
  normalizeWakePayload,
  readJsonBody,
  resolveHookSessionKey,
  resolveHookTargetAgentId,
  resolveHookChannel,
  resolveHookDeliver,
} from "./hooks.js";

import { sendGatewayAuthFailure, setDefaultSecurityHeaders } from "./http-common.js";

import { getBearerToken } from "./http-utils.js";

import { handleOpenAiHttpRequest } from "./openai-http.js";

import { handleOpenResponsesHttpRequest } from "./openresponses-http.js";

import { GATEWAY_CLIENT_MODES, normalizeGatewayClientMode } from "./protocol/client-info.js";

import type { GatewayWsClient } from "./server/ws-types.js";

import { handleToolsInvokeHttpRequest } from "./tools-invoke-http.js";



// yha pr do cheezein aati hain ek toh javascript wala typeof aur ek typescript wala typeof.
// JavaScript mein agar tum typeof "hello" likhoge toh woh "string" dega. 
// Par TypeScript ke andar, typeof ek X-Ray Machine ban jata hai.
// aur yha pr hum typescript wala typeof dekh rhe hain.
// Yeh typeof createSubsystemLogger function ko chalata (execute) nahi hai. 
// Yeh bas uska X-Ray nikalta hai aur dekhta hai ki: "Yeh function kitne parameters leta hai? Aur return kya karta hai?" 
// Isey technical bhasha mein Function Signature bolte hain.
// uske baad aata h ReturnType.
// iska bs ek hi kaam h. "Mere < > brackets ke andar kisi bhi function ka X-Ray (typeof) daal do, main usme se input parameters ko kachre mein phek dunga, aur sirf uski Return Value ka naksha (type) bacha kar bahar nikalunga."
type SubsystemLogger = ReturnType<typeof createSubsystemLogger>;



// Hackers scripts likhte hain jo ek second mein 10,000 alag-alag passwords ya tokens guess kar sakti hain. 
// Isey Brute-Force Attack kehte hain.
// Server ko apne paas ek counter rakhna padta hai. "Agar koi lagataar galat password daal raha hai, toh usko thodi der ke liye block kar do."
// Block karne ke liye do rules chahiye: Kitni galtiyan allowed hain? Aur kitne time frame mein?

// Server kisi bhi IP address ya user ko maximum 20 baar galat password/token daalne ki permission dega.
const HOOK_AUTH_FAILURE_LIMIT = 20;

// Yeh 60,000 milliseconds (yani exactly 1 Minute) ka timer hai.
const HOOK_AUTH_FAILURE_WINDOW_MS = 60_000;

// "Agar kisi ne 1 minute ke andar 20 baar galat Auth Token bheja, toh usko block kar do aur aage uski request check bhi mat karo."





// Yeh ek 'Remote Control' ka blueprint hai jisme sirf 2 buttons hain. 
// Ek button AI ka alarm bajata hai, 
// aur doosra button AI ko ek lamba task dekar ek Tracking ID (Receipt) wapas deta hai.
type HookDispatchers = {
  // Button 1: The "Wake" Button
  // Yeh button do cheezein leta hai: Ek message (text) aur Urgency (mode ki abhi jagau ya agli heartbeat pe?).
  // Yeh void return karta hai. 
  // Iska matlab hai "Fire and Forget". 
  // Tumne alarm baja diya, ab tumhe is function se koi jawaab (return) nahi chahiye. Server ko wait nahi karna padega.
  dispatchWakeHook: (value: { text: string; mode: "now" | "next-heartbeat" }) => void;

  // Button 2: The "Agent Task" Button
  // Yeh poora ka poora task (Payload) leta hai (jaise kaunsa model, kya message, kya tools).
  // Notice karo: Yeh ek string return karta hai.
  dispatchAgentHook: (value: HookAgentDispatchPayload) => string;
};



// Jab ek server client ko response bhejta hai, toh us (Response) ke 3 main hisse hote hain:
  // Status Code: Baat kaisi rahi? (Good, Bad, Error?)
  // Headers: Lifafe ke upar ki jankari (Andar kya bhara hai?)
  // Body: Asli saamaan (Data).
// Yeh function in teeno ko ek hi jhatke mein set karke parcel dispatch kar deta hai.
function sendJson(res: ServerResponse, status: number, body: unknown) {

  // Yeh client ko batata hai ki request ka nateeja kya nikla.
  res.statusCode = status;
  
  // Agar tum yeh nahi likhoge, toh client ka browser sochega ki tumne usko ek normal text file ya HTML file bheji hai, aur data ajeeb sa dikhega.
  // Yeh ek sticker hai jo lifafe par lagta hai. Yeh client ko bolta hai: "Bhai, andar jo text hai usko normal text mat samajhna, woh ek JSON object hai. Usko parse kar lena." charset=utf-8 ensure karta hai ki emojis aur doosri languages ke characters sahi se dikhein.
  res.setHeader("Content-Type", "application/json; charset=utf-8");

  // JSON.stringify(body): JavaScript ke object/array ko ek simple string (text) mein convert karta hai, kyunki internet par data sirf text/bytes ke format mein travel kar sakta hai.
  // res.end(...): Yeh final thappa hai. Yeh data ko connection ke pipe mein daalta hai aur pipe ko band kar deta hai. "Mera jawaab khatam, ab call cut karo."
  res.end(JSON.stringify(body));
}



// Yeh function bas ek list check karke true ya false mein jawaab deta hai ki aane wali request OpenClaw ke "Canvas (Interactive UI)" department ki hai ya nahi.
function isCanvasPath(pathname: string): boolean {
  return (
    pathname === A2UI_PATH ||
    pathname.startsWith(`${A2UI_PATH}/`) ||
    pathname === CANVAS_HOST_PATH ||
    pathname.startsWith(`${CANVAS_HOST_PATH}/`) ||
    pathname === CANVAS_WS_PATH
  );
}



// Yeh function check karta hai ki Gateway se judne wala naya WebSocket client koi aam user (Browser/UI) hai, ya phir OpenClaw ka hi koi internal worker/AI Agent (Node) hai?

// Sach 1 (The Pipes): WebSocket ek khuli hui pipe hoti hai jisme data dono taraf continuously flow karta hai.
// Sach 2 (The Clients): OpenClaw Gateway se 2 tarah ke log is pipe ke through judte hain:
// Frontend UI (Browser): Jo sirf yeh dekhna chahta hai ki "AI ne kya type kiya?" (Read-heavy).
// Worker Nodes (Sub-agents/Runners): Jo doosri machines par baithe hain aur Gateway se bolte hain: "Bhai koi naya heavy task hai toh mujhe de, main process karke wapas bhejta hu."
// Gateway ko in dono ke beech farq pata hona chahiye, taaki galti se kisi normal user ko "Background Job" process karne ko na de de! Yeh function wahi "Identity Test" hai.

// Yeh function true return karta hai agar client ek "Node" (Worker) hai ya nhi, aur uske liye yeh 2 checks lagata hai:
function isNodeWsClient(client: GatewayWsClient): boolean {

  // Check 1: The Direct Badge
    // Kya hai: Jab client connect hota hai, toh woh apna connect object bhejta hai. Agar usne saaf-saaf apna role "node" set kiya hua hai, toh function turant true bol deta hai. (Yeh sabse fast aur modern tareeqa hai).
  if (client.connect.role === "node") {
    return true;
  }

  // Check 2: The Legacy/Mode Fallback
    // Agar role define nahi tha, toh function client ke purane details (mode) ko check karta hai.
    // Client kisi purane version se ya ajeeb casing (jaise "NoDe", " NODE ") mein data bhej sakta hai. Yeh normalize function us kachre ko saaf karke ek standard format mein laata hai, aur phir check karta hai ki kya woh standard GATEWAY_CLIENT_MODES.NODE se match ho raha hai. 
  return normalizeGatewayClientMode(client.connect.client.mode) === GATEWAY_CLIENT_MODES.NODE;
}

// ek kahani

// 🎭 The Setup (Kahaani Ke Kirdaar)
// The AI Agent (The Chef): Jo background mein soch raha hai aur UI (Canvas) ke liye code/data bana raha hai.
// The Gateway (The Bouncer): OpenClaw ka main server, jo saare connections (WebSockets) ko handle karta hai.
// The User (You): Jo browser mein baith kar live output dekhna chahta hai.
// The Hacker (The Snoop): Jo bina permission ke tumhara data dekhna chahta hai.

// 🟢 Flow 1: The AI Agent Flow (The Setup)
// Yeh flow tab chalta hai jab tum prompt dete ho: "Make a snake game in Canvas".
// Thinking & Decision: AI Agent ko samajh aata hai ki mujhe Canvas UI kholna padega.
// Generating the Secret: Agent turant ek bohot lamba, random password generate karta hai (e.g., secret_77xyz99). Isey hum Capability Token kehte hain.
// Registering with the Bouncer: Agent apne secure WebSocket connection ke through Gateway (Bouncer) ko bolta hai: "Bhai, main apna Canvas khol raha hu. Mera secret password secret_77xyz99 hai. Yeh aane wale 5 minute tak valid rahega."
// Sending the Link to User: Agent tumhari normal chat screen par ek button/link bhej deta hai, jiske andar woh password chupa hota hai: https://openclaw.com/canvas?oc_cap=secret_77xyz99.

// 🔵 Flow 2: The Legit User Flow (The Golden Path)
// Yeh flow tab chalta hai jab tum us 'Open Canvas' button pe click karte ho.
// The Click: Tumne button dabaya. Tumhara browser background mein ek naya WebSocket connection (live pipe) kholne ki koshish karta hai Gateway ke sath.
// Presenting the Passcode: Browser Gateway ko bolta hai: "Mujhe Canvas se judna hai, aur mere paas yeh pass hai: ?oc_cap=secret_77xyz99."
// The Gateway Check (Woh Function!): Gateway turant wahi function (hasAuthorizedNodeWsClientForCanvasCapability) chalata hai.
// Gateway dekhta hai: "Kya andar koi AI Agent baitha hai jiska password secret_77xyz99 hai?"
// Match Found!
// The Live Stream: Gateway tumhare browser aur us AI Agent ki pipe ko aapas mein jod deta hai. Ab AI Agent jo bhi code likhega, woh directly tumhari screen (Canvas) par live animate hoga!
// Sliding Window: Jab tak tum us page par ho aur data flow ho raha hai, Gateway us 5 minute ke timer ko aage badhata rehta hai taaki tumhara connection toote na.

// 🔴 Flow 3: The Hacker Flow (The Block)
// Ab socho ek hacker, jiska naam Bob hai, usko pata chal gaya ki tum OpenClaw use kar rahe ho.

// Scenario A: The Guesser
// Bob apne browser mein type karta hai: https://openclaw.com/canvas. (Bina kisi token ke).
// Gateway dekhta hai: "Token kahan hai bhai?" aur turant connection kaat deta hai (403 Forbidden). Bob ko blank screen dikhti hai.

// Scenario B: The Brute-Forcer
// Bob script lagata hai aur random tokens try karta hai: ?oc_cap=123, ?oc_cap=abc.
// Gateway function chalata hai. Usko apne andar zinda AI Agents ki list mein aisi koi 'Capability' milti hi nahi. Woh connection kaat deta hai. (Aur yaad hai humne pichli files mein Rate Limiter padha tha? 20 baar aisi harkat karne par Gateway Bob ka IP hi block kar dega!).

// Scenario C: The Latecomer (Expired Token)
// Bob ne galti se tumhara purana link copy kar liya jo tumne kal use kiya tha: ?oc_cap=old_secret_111.
// Gateway dekhta hai: "Haan, yeh password kal ek Agent ne use toh kiya tha, par uski ExpiresAtMs limit kal hi khatam ho chuki hai!"
// Connection Dropped. Bob fails again.

// 💡 The Master Question: "Token browser cookie mein kyu nahi rakha? URL mein kyu bheja?"
// Agar hum tumhari main chat wali ID/Cookie use karte, toh Gateway ko pehle Database mein jaakar check karna padta ki "Kya is user ne yeh agent start kiya tha?". Database checking slow hoti hai.

// Capability Token (oc_cap) URL mein bhejkar humne Gateway ka kaam ekdum fast (Stateless) kar diya. Gateway ko database check nahi karna, usko bas apne RAM mein baithe zinda AI connections ki list mein password match karna hai. O(N) memory search! Fast and Secure.




// Yeh function check karta hai ki kya server par koi aisa zinda AI Agent (Node) connected hai jisne Canvas UI ko control karne ka woh 'Secret Passcode' (Capability) generate kiya tha?
function hasAuthorizedNodeWsClientForCanvasCapability(

  // Yeh un sabhi WebSockets ki ek list hai jo is waqt tumhare OpenClaw server se connected hain.
  clients: Set<GatewayWsClient>,

  // Yeh wahi secret token hai jo Browser (User) ne URL mein bheja tha (?oc_cap=secret_77xyz99). Yeh woh chabi hai jiska tala humein us clients ki bheed mein dhoondhna hai.
  capability: string,

  // Ya toh true (Andar aane do), ya false (Bahar nikal do).
): boolean {
  
  // abhi ka time nikal liya aur nowMs, variable m daal lia
  const nowMs = Date.now();
  
  // yha ek ek krke jo bhi connected clients h unme check hoga.
  for (const client of clients) {
  
    // Kya yeh client ek AI Agent (Node) hai?" Agar normal user (Browser) hai, toh usko ignore karo (continue), kyunki Canvas permissions sirf AI Agents ke paas hoti hain.
    if (!isNodeWsClient(client)) {
      continue;
    }
  
    // Kya is Agent ne Canvas ka feature on kiya hua hai aur expiry time set kiya hai?" 
    // Agar nahi, toh ignore.
    if (!client.canvasCapability || !client.canvasCapabilityExpiresAtMs) {
      continue;
    }
  
    // Kya is Agent ki Canvas access expire ho chuki hai?" 
    // Agar time nikal gaya hai, toh ignore. 
    // (Yeh security ke liye zaroori hai taaki purane links hamesha ke liye na chalte rahein).
    if (client.canvasCapabilityExpiresAtMs <= nowMs) {
      continue;
    }
  
    // "Kya user ka password aur Agent ka password match ho gaya?" Agar haan, toh andar aane do!
    // humne safequalsecret use kiya h kyuki safeEqualSecret chahe 1st letter galat ho ya 100th, hamesha exact same time (e.g., 2ms) lega result dene mein.
    if (safeEqualSecret(client.canvasCapability, capability)) {
      // Sliding expiration while the connected node keeps using canvas.

      // Agar password match ho gaya, toh server bolta hai: "Chalo bhai, pass toh sahi hai. Aur kyunki tumne abhi-abhi apna pass dikhaya hai, iska matlab tum abhi zinda/active ho. Main tumhare pass ki expiry ko abhi ke time (nowMs) se theek 5 minute aage dhakel raha hu."
      client.canvasCapabilityExpiresAtMs = nowMs + CANVAS_CAPABILITY_TTL_MS;
      return true;
    }
    
  }
  
  return false;
}



// Yeh Canvas UI ka "Master Security Checkpoint" hai. Yeh 4 alag-alag tareeqon se check karta hai ki aane wala aadmi Canvas access karne ke laayak hai ya nahi. Agar ek bhi tareeqe se pass ho gaya, toh entry mil jati hai.
async function authorizeCanvasRequest(params: {
  req: IncomingMessage;
  auth: ResolvedGatewayAuth;
  trustedProxies: string[];
  allowRealIpFallback: boolean;
  clients: Set<GatewayWsClient>;
  canvasCapability?: string;
  malformedScopedPath?: boolean;
  rateLimiter?: AuthRateLimiter;
}): Promise<GatewayAuthResult> {

  const {
    req,
    auth,
    trustedProxies,
    allowRealIpFallback,
    clients,
    canvasCapability,
    malformedScopedPath,
    rateLimiter,
  } = params;
  
  if (malformedScopedPath) {
    return { ok: false, reason: "unauthorized" };
  }
  
  if (isLocalDirectRequest(req, trustedProxies, allowRealIpFallback)) {
    return { ok: true };
  }

  let lastAuthFailure: GatewayAuthResult | null = null;
  
  const token = getBearerToken(req);
  
  if (token) {
    const authResult = await authorizeHttpGatewayConnect({
      auth: { ...auth, allowTailscale: false },
      connectAuth: { token, password: token },
      req,
      trustedProxies,
      allowRealIpFallback,
      rateLimiter,
    });
  
    if (authResult.ok) {
      return authResult;
    }
  
    lastAuthFailure = authResult;
  }

  if (canvasCapability && hasAuthorizedNodeWsClientForCanvasCapability(clients, canvasCapability)) {
    return { ok: true };
  }
  
  return lastAuthFailure ?? { ok: false, reason: "unauthorized" };
}




function writeUpgradeAuthFailure(
  socket: { write: (chunk: string) => void },
  auth: GatewayAuthResult,
) {
  if (auth.rateLimited) {
    const retryAfterSeconds =
      auth.retryAfterMs && auth.retryAfterMs > 0 ? Math.ceil(auth.retryAfterMs / 1000) : undefined;
    socket.write(
      [
        "HTTP/1.1 429 Too Many Requests",
        retryAfterSeconds ? `Retry-After: ${retryAfterSeconds}` : undefined,
        "Content-Type: application/json; charset=utf-8",
        "Connection: close",
        "",
        JSON.stringify({
          error: {
            message: "Too many failed authentication attempts. Please try again later.",
            type: "rate_limited",
          },
        }),
      ]
        .filter(Boolean)
        .join("\r\n"),
    );
    return;
  }
  socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
}




export type HooksRequestHandler = (req: IncomingMessage, res: ServerResponse) => Promise<boolean>;






// The Webhook Engine (createHooksRequestHandler)

// Ye is file ka sabse heavily-engineered hissa hai.
// Jab koi external system (maan le Stripe ya tera apna frontend) ek POST request bhejta hai kisi Agent ko jagane (wake) ke liye:
// Ye function token verify karta hai.
// JSON body ko parse karta hai (readJsonBody) aur limit check karta hai taaki server crash na ho.
// Phir decide karta hai ki Agent ko jaga kar usko kya payload (message) dena hai (dispatchAgentHook).

// Agar hum ek Webhook (bahar se aane wali request) ko first principles se sochein, toh 4 basic cheezein hoti hain yha:

// 1. Identity: Koi mere (server) pr aaya hai. Kya main isko jaanta hu? Is it (Authenticated?)
// 2. Capacity: Kahin ye ek saath 100 baar door-bell bajakar mujhe pareshan toh nahi kar raha? (Rate Limiting)
// 3. Understanding: Ye jo bol raha hai, kya mujhe samajh aa raha hai? (Body Parsing)
// 4. Action: Ye kiske liye message laya hai aur kya response dena hai? (Routing & Dispatching)

export function createHooksRequestHandler(
  opts: {
    // hum yahan static data (ruka hua data) bhejne ke bajaye ek dynamic function bhej rahe hain. Isse jab bhi koi naya webhook aayega, server hamesha latest settings fetch karega. Aur | null ka matlab hai ki agar admin ne webhooks disable kar diye hain, toh system crash nahi hoga, bas chup-chaap us request ko ignore kar dega.
    // Par yahan developer ne () => (arrow function) laga kar ek "getter" bana diya. Ab jab bhi raat ko 2 baje koi Stripe ya external API ki request aayegi, yeh function us exact second mein run hoga aur database/memory se ekdum fresh configuration layega.
    // getHooksConfig ek function hai jo koi parameter nahi leta aur HooksConfigResolved ya null return karta hai.
    getHooksConfig: () => HooksConfigResolved | null;

    
    // Server ko pata hona chahiye ki usko kis IP address (host) par requests sunni (listen karni) hain. 
    // Yeh ek text value store karega, jaise "0.0.0.0" ya "localhost".
    bindHost: string;

    // Ek hi address (host) par bahut saare programs chal sakte hain. Port batata hai ki kis darwaze par aana hai.
    // Yeh OS ko bolta hai ki is specific number (jaise 3000 ya 8080) par aane wale internet traffic ko is program tak bhejo.
    // bindHost aur port milkar base URL banate hain valid requests verify karne ke liye.
    port: number;

    // Agar server mein koi webhook fail ho jaye ya koi error aaye, toh hume pata kaise chalega? Isliye ek diary (logger) maintain karni padti hai.
    // Yeh ek pre-configured object hota hai jisme warn(), info(), error() jaise functions hote hain jo terminal ya file mein text print karte hain.
    logHooks: SubsystemLogger;

    // TypeScript ka feature hai jisko "Intersection Type" kehte hain. Yeh bolta hai ki opts ke andar purani wali 4 cheezein toh hongi hi, saath mein HookDispatchers ke andar jo bhi functions hain (jaise dispatchAgentHook), woh bhi include honge.
  } & HookDispatchers,
): HooksRequestHandler {


  const { getHooksConfig, bindHost, port, logHooks, dispatchAgentHook, dispatchWakeHook } = opts;

  // Jab koi webhook (jaise Stripe ya GitHub) tere server par hit karta hai, toh usko ek Secret Token dena padta hai. 
  // Par agar koi hacker script laga kar har second 1000 alag-alag tokens try karne lage (jise Brute-Force Attack kehte hain), toh tera server crash ho jayega. 
  // Ye config usi attack ko rokne ka blueprint hai.
  const hookAuthLimiter = createAuthRateLimiter({

    // The Rule (Limit & Time): Ye dono lines mil kar ek rule banati hain. Maan le limit 20 hai aur window 60,000ms (1 minute) hai.
    // Iska matlab Bouncer keh raha hai: "Main ek IP address ko 1 minute ke andar sirf 20 baar galat password daalne dunga."
    maxAttempts: HOOK_AUTH_FAILURE_LIMIT,
    windowMs: HOOK_AUTH_FAILURE_WINDOW_MS,

    // Agar kisi hacker ne 1 minute mein 20 baar galat token daal diya, toh ab kya?
    // Ye line usko seedha lockoutMs (e.g., aakhri attempt ke baad agle 1 minute tak) ke liye block kar degi. Ab wo chahe sahi password bhi daal de, Bouncer usko HTTP 429 (Too Many Requests) dekar bhaga dega.
    lockoutMs: HOOK_AUTH_FAILURE_WINDOW_MS,

    // Loopback ka matlab hota hai "Localhost" (matlab usi same machine se aane wali request).
    // Ek Junior dev isko true kar deta ye soch kar ki "Jo request mere hi server ke andar se aa rahi hai, wo toh safe hi hogi na!"
    // Par ek SDE-1 jaanta hai ki agar hacker ne kisi aur vulnerability (jaise SSRF - Server Side Request Forgery) ke through server ke andar ghus kar attack kiya, toh system toot jayega. false ka matlab hai: "Chahe request andar se aaye ya bahar se, security sabke liye barabar hai."
    exemptLoopback: false,
    
    // Handler lifetimes are tied to gateway runtime/tests; skip background timer fanout.
    pruneIntervalMs: 0,
  });

  // Is File Ka Main Kaam: Jo bhi external system humein request bhej raha hai, uska IP address nikalna aur usko ek clean, standard format mein convert karna, taaki hum usko pehchaan sakein.
  const resolveHookClientKey = (req: IncomingMessage): string => {

    // Yeh line network connection (socket) se bhejne wale ka IP address (remoteAddress) nikalti hai, usko saaf karne ke liye ek doosre function (normalize...) ko deti hai, aur jo final result aata hai use wapas bhej deti hai (return).
    // IP addresses ke alag-alag format hote hain. Jaise IPv4 (192.168.1.1) aur IPv6 (::ffff:192.168.1.1). Agar hum inko standard format mein (normalize) nahi karenge, toh computer inko do alag machines samajh lega, jabki asal mein ek hi machine hoti hai.
    // req.socket us physical network connection ko darshata hai jiske through data aaya. Us connection ka ek property hota hai remoteAddress (samne wale ka pata). Phir normalizeRateLimitClientIp function is address par jo faltu characters hote hain, unko hata kar ek clean IP de deta hai.
    return normalizeRateLimitClientIp(req.socket?.remoteAddress);
  };

  // Jab bhi baahar se koi request aati hai, woh sabse pehle is block se takrati hai.
  // Jab bhi HTTP request aati hai, server is function ko bulata hai. req mein aane wale ka saara data (URL, IP) hota hai, aur res ke through hum wapas jawaab bhejte hain.
  return async (req, res) => {

    // Yeh line system ki latest settings (hooksConfig) mangwa rahi hai getHooksConfig() function ko call karke.
    const hooksConfig = getHooksConfig();
    
    // Agar settings hi load nahi hui hain (ya webhooks disable hain), toh request aage process karne ka koi matlab nahi hai. Server error se bachane ke liye early exit.
    if (!hooksConfig) {
      return false;
    }
    
    // req.url sirf /api/webhook jaisa aadha-adhura rasta deta hai. Humein query parameters, paths sab alag-alag chahiye hote hain, isliye usko new URL mein daalna zaroori hai.
    // server ko koi request milti h, POST /hooks/agent?user=123, nodejs server ko ek req object milta h yha pr, req, usme ek property hoti hai req.url, req.url sirf path hota hai, full url nhi, mtlb req.url sirf /hooks/agent hoga, but kabhi kabhi humein poore url ki bhi zarurat pd skti h "http://localhost:3000/hooks/agent".
    const url = new URL(req.url ?? "/", `http://${bindHost}:${port}`);
    // url variable k andar string nahi balki url object store hota h. for example:
    // url = {
    //   href: "http://localhost:3000/hooks/agent?token=123",
    //   protocol: "http:",
    //   hostname: "localhost",
    //   port: "3000",
    //   pathname: "/hooks/agent",
    //   search: "?token=123",
    //   searchParams: URLSearchParams { token: "123" }
    // }

    
    // hmare server pr bahut sarey routes ho sktey h alg alg services k liye jaise, /login, /users, /products, /hooks, /hooks/agents etc. or hr route ka alg alg kaam hota h. jaise, 
    // /login → user login,
    // /products → products list
    // /orders → order create
    // /hooks → webhook requests
    // aur webhook ka mtb hota h, jb koi external system server ko automatically koi event bhejta h, uss event ko boldete h webhook. jaise stripe pr payment successful hua, toh stripe ne automatically ek post request iss route /hooks/payment pr bhej di. 
    // ab aata h webhook system, iska kaam hota h, external systems se aane wali requests handle karna, but jo webhook system h wo sirf webhook routes hi handle krega. mtlb /hooks/*; 
    // isliye toh hum keh skte h ki; Webhook system ko sirf hooks wale routes handle karne hain.
    // isliye configuration m ek base path define hota h. 
    // hooksConfig = {
    //   basePath: "/hooks",
    //   token: "secret123"
    // }
    // toh wha se humne isko nikal liya
    // ab jaise koi request aai, /hooks/agent, yha basePath -> /hooks ho jayega, toh webhook handler bolega han ye mera route h isko main process krunga. otherwise main isko process nhi krunga.
    const basePath = hooksConfig.basePath;
    
    if (url.pathname !== basePath && !url.pathname.startsWith(`${basePath}/`)) {
      return false;
    }



    // ab webhook ki request aagyi server k pass, ab server ko usko authenticate bhi krna hota h. mtlb server confirm krega ki request trusted system se aai h ya nhi. isliye token ka use kiya jata hai. 
    
    // example 
    // POST /hooks/agent
    // Authorization: Bearer secret-token

    // Koi request aise bhi bhej sakta hai:
    // POST /hooks/agent?token=secret-token
    // Yaha token URL query parameter me hai.
    // Example URL:
    // http://localhost:3000/hooks/agent?token=abc123
    // Ye unsafe practice hai.

    // toh sbse pehle hum check kr rhe hain, kya URL query parameters me "token" hai? mtlb token kuch aise h? /hooks/agent?token=abc123, agr hn, toh server turant request ko reject kr dega, status code 400 bhej kr. 400 bad request. mtlb client ne galat format me request bheji. agr token url m exist kr rha h, 
    // Toh token leak ho sakta hai: 
      // Server logs me URL store ho jata hai. 
      // URL history me save ho sakta hai. 
      // CDN / proxy logs me bhi save ho sakta hai.
    if (url.searchParams.has("token")) {
      res.statusCode = 400;

      // iska mtlb response plain text m bheja jayega, 
      res.setHeader("Content-Type", "text/plain; charset=utf-8");

      // yha server client ko message bhej rha h, ki token url m mt bhejo, header m bhejo. 
      res.end(
        "Hook token must be provided via Authorization: Bearer <token> or X-OpenClaw-Token header (query parameters are not allowed).",
      );

      // true ka mtlb request handle ho chuki hai, response bhi ja chuka h. aur aagey code execute nhi hoga. 
      return true;
    }

    // ab server ne ye bhi check krliya ki token url m nhi h, header m h, toh chlo usko wha se nikal lete h. ye wala function, extractHookToken, hmari server pr aai hui request se authentication token nikal rha h.
    // iska example du agr main. 
    // POST /hooks/agent
    // Authorization: Bearer abc123
    // token = "abc123"
    // aur aisa hum isliye krtey hain kyuki server ko check krna hota h ki request ek trusted system se aai hai ya nhi, agr trusted system se aai hogi toh token bhi correct hoga, iss token ko hum badmein apne pass rkhe token se match krwaingey. agr match nhi hua mtlb trusted system se request nhi aai, 401 unauthorized error phek do.
    const token = extractHookToken(req);
    
    // ye function request se client identifier nikal rha h. mtlb client ip address. oopar humne yhi function bnaya hai.
    const clientKey = resolveHookClientKey(req);
    

    // theek hai toh chaliye aagey bhdtey hain, isko bhi hum first principle se hi dekhengey. iss block ka kaam ye h ki, jo request aai h server k pass, uska token check krega ye, agr token galat nikla, toh ye bhi check hoga ki kahin yeh banda baar-baar toh galat password nahi daal raha. Agar limit cross ho gayi, toh isko block kar dena.
    if (!safeEqualSecret(token, hooksConfig.token)) {
      // ye safeEqualSecret check kr rha h ki, token correct h ya nhi, agr correct hoga token toh toh ye block execute nhi hoga, wo toh request phir normally allow hi ho jayegi, pr agr token galat nikla tb hum ye if block chlaingey. theek h. aur ye aisa hum isliye kr rhe hain kyuki yha pr timing attacks ka ek concept aata h. agr hum direct ye === use kringey. toh jiss character ya word pr match nhi hua aaya hua naya token already existing token se, wohi error throw krdega, aur aise hi multiple guesses krkr ke ek hacker token guess kr skta h aur infilterate kr skta h. 
      // but jb hum safeEqualSecret use krtey h, toh wo hmesha exact same time leta h, password check karne mein, chahe pehla letter galat ho ya aakhri. 
      // Agar password match nahi hota, toh yeh condition true ho jayegi aur code is block ke andar ghus jayega.


      const throttle = hookAuthLimiter.check(clientKey, AUTH_RATE_LIMIT_SCOPE_HOOK_AUTH);
      // chlo isko dekhtey h first principle se. humein server ko protect krna hota h attackers se. 
      // Example attacker kya karega:
        // POST /hooks/agent
        // token=abc
        // token=abcd
        // token=abcde
        // token=abcdef
        // ...
      // Matlab hazaron requests bhejkar token guess karne ki koshish karega. Isko bolte hain: Brute force attack. aur iska solution hai rate limiting. mtlb ek client kitni bar request try kr skta h, uski limit set krdo.
      // hookAuthLimiter: Ye basically ek rate limiter object hai. Iska kaam: track karo kis IP ne kitni requests kri h.
      // ab aaya check method, check method dekhta h: kya is client ko request karne ki permission hai Matlab internally ye check karega: last 1 minute me kitne attempts hue
      // cient key: client ka ip address hogya. 
      // Phir aata h AUTH_RATE_LIMIT_SCOPE_HOOK_AUTH. Ye basically rate limit ka category / scope hai. Matlab limiter different types ke limits rakh sakta hai. Example: login attempts, API calls, webhook auth, Yaha specifically limit ho rahi hai: webhook authentication attempts.
      // ab dekhtey hain throttle variable mein kya aata h. check() toh ek result object return krta h.
      // Example:

      // throttle = {
      //   allowed: true,
      //   retryAfterMs: 0
      // }

      // Ya agar limit cross ho gayi:

      // throttle = {
      //   allowed: false,
      //   retryAfterMs: 60000
      // }

      // Meaning:
        // allowed = request allowed hai ya nahi
        // retryAfterMs = kitni der baad retry kar sakte ho
      // 



      // yha pr hum server ko protect kr rhe hain, too many requests se, brute force attacks se.
      // throttle.allowed btata h ki kya client ko request krne ki permission h ya nhi.
      // toh agr request allowed nhi h toh ye wala block execute hoga.
      // retryAfter : client ko kitne seconds baad retry karna chahiye
      if (!throttle.allowed) {

        // Ye line milliseconds me diye gaye retry time ko seconds me convert karke retryAfter variable me store karti hai, taaki client ko bataya ja sake ki kitne seconds baad request dubara try karni chahiye.
        const retryAfter = throttle.retryAfterMs > 0 ? Math.ceil(throttle.retryAfterMs / 1000) : 1;

        // 429 ka mtlb hota h too many request.
        res.statusCode = 429;

        // yha pr aatey aatey humein pta chl gya hai ki client ne bahut sari requests bheji hain. 
        // iss line m HTTP header set ho rha h, Retry-After: 60
        // kyuki yha pr hum client ko bta rhe hain ki abhi request mt bhejo 60 seconds baad bhejna.
        // res.setHeader ka kaam h, response ka header set krna. aur ye "Retry-After" ek standard header h.
        res.setHeader("Retry-After", String(retryAfter));

        // iss line ka mtlb h ki, server ye bta rha h ki, main response plain text mein bhej rha hu. kyuki client ko pta hona chahiye ki response ka format kya h.
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        
        // yha pr Server response bhej raha hai aur connection close kar raha hai. ye message client k pass chla jayega, aur yha pr response complete ho jaygea iske bad koi aur response nhi jayega.
        res.end("Too Many Requests");
        
        // aur yha pr server ne apne internal log mein ek warning ki entry krdi.
        logHooks.warn(`hook auth throttled for ${clientKey}; retry-after=${retryAfter}s`);
        
        // return true mtlb, hum function ko bta rhe h ki request handle ho chuki h.
        return true;
      }
      // Client ne zyada requests bheji
      //         ↓
      // Server ne block kiya
      //         ↓
      // Retry time diya (Retry-After)
      //         ↓
      // Message diya (Too Many Requests)
      //         ↓
      // Log store kiya
      //         ↓
      // Request end



      // toh oopar wala block chla tha jb client bar bar galat password/token k sath request bhej rha h aur request limit exceed ho gyi hai. 
      // pr ye neeche wala code tb chlega jb user ne galat password/token toh bheja pr request limit abhi exceed nhi hui h, toh server kya krega chliye dekhtey h.

      // ye line system ko bol rhi h, ki is specific client (IP address) ke aage ek "galti" (failure) ka mark laga do. kyuki iska password/token galat h.
      // Yeh memory (ya database) mein us clientKey ke khaate mein failure count ko +1 kar deta hai. AUTH_RATE_LIMIT_SCOPE_HOOK_AUTH bas ek tag hai jo batata hai ki yeh webhook authentication ki galti thi.
      hookAuthLimiter.recordFailure(clientKey, AUTH_RATE_LIMIT_SCOPE_HOOK_AUTH);
      
      // yha response ka status code set kr rhe h. 401 means unauthorized.
      res.statusCode = 401;
      
      // Yeh line response ke saath ek (header) chipka rahi hai jo samne wale ko batayega ki aane wala message kis bhasha/format mein hai.
      // toh server ye bta rha h ki, main response plain text mein bhej rha hu. kyuki client ko pta hona chahiye ki response ka format kya h, jissey wo frontend m respone ko sahi se parse kr ske.
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      
      // Yeh server ki aakhri baat hai. Yeh plain text message "Unauthorized" bhej kar connection ko kaat (close) raha hai.
      // Agar hum res.end() (ya res.send()) call nahi karenge, toh client ka browser ya server infinite time tak ghoomta (loading) rahega, server ke wait mein. Connection band karna zaroori hai.
      res.end("Unauthorized");
      
      return true;
    }


    // yeh block tab chalta hai jab token bilkul sahi nikalta hai!
    // Password sahi nikalne ke baad, server us client ka purana record saaf karta hai
    // Yeh line rate limiter (security guard) ko bol rahi hai ki is IP (clientKey) ke naam par jitne bhi pichle fail attempts (failed logins) darj hain, un sabko mita do (reset kar do).
    hookAuthLimiter.reset(clientKey, AUTH_RATE_LIMIT_SCOPE_HOOK_AUTH);


    // Webhooks ka ek hi kaam hota hai: Ek server se dusre server tak data bhejna. Internet par data bhejne ke liye POST method use hota hai. Agar koi GET (sirf data mangne wala) ya DELETE method se aa raha hai, toh iska matlab woh webhook ke rules tod raha hai.
    if (req.method !== "POST") {

      // Agar method POST nahi hai, toh response ka status error code 405 set kar do.
      // API ki duniya mein jab rasta sahi ho (URL sahi ho) lekin baat karne ka tareeqa (Method) galat ho, toh 404 Not Found nahi dete, balki 405 Method Not Allowed dete hain. Yeh standard rule hai.
      res.statusCode = 405;

      // Ek special response header set ho raha hai jiska naam hai "Allow", aur uski value hai "POST".
      // 🎯 KYU HAI	Jab aap kisi ko 405 Method Not Allowed error dete ho, toh API standards (RFC 7231) ke mutabiq aapko usko yeh bhi batana hota hai ki "Bhai, agar yeh allowed nahi hai, toh phir kya allowed hai?". Yeh ek good developer practice hai.
      res.setHeader("Allow", "POST");
      
      // Puraani line jaisi hi hai, bas bata rahi hai ki jo error message abhi aayega, woh plain text format mein hai.
      res.setHeader("Content-Type", "text/plain; charset=utf-8");

      // yha pr humne connection ko complete kr diya ek respones k sath. connection end krna zaruri hota hai.
      res.end("Method Not Allowed");

      // return true krdiya, mtlb function ko retun krwa rhe hain, jissey ki iske neeche ka faltu code run na kre.
      return true;
    }

    // 
    const subPath = url.pathname.slice(basePath.length).replace(/^\/+/, "");

    if (!subPath) {
      res.statusCode = 404;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("Not Found");
      return true;
    }

    const body = await readJsonBody(req, hooksConfig.maxBodyBytes);
    if (!body.ok) {
      const status =
        body.error === "payload too large"
          ? 413
          : body.error === "request body timeout"
            ? 408
            : 400;
      sendJson(res, status, { ok: false, error: body.error });
      return true;
    }

    const payload = typeof body.value === "object" && body.value !== null ? body.value : {};
    const headers = normalizeHookHeaders(req);

    if (subPath === "wake") {
      const normalized = normalizeWakePayload(payload as Record<string, unknown>);
      if (!normalized.ok) {
        sendJson(res, 400, { ok: false, error: normalized.error });
        return true;
      }
      dispatchWakeHook(normalized.value);
      sendJson(res, 200, { ok: true, mode: normalized.value.mode });
      return true;
    }

    if (subPath === "agent") {
      const normalized = normalizeAgentPayload(payload as Record<string, unknown>);
      if (!normalized.ok) {
        sendJson(res, 400, { ok: false, error: normalized.error });
        return true;
      }
      if (!isHookAgentAllowed(hooksConfig, normalized.value.agentId)) {
        sendJson(res, 400, { ok: false, error: getHookAgentPolicyError() });
        return true;
      }
      const sessionKey = resolveHookSessionKey({
        hooksConfig,
        source: "request",
        sessionKey: normalized.value.sessionKey,
      });
      if (!sessionKey.ok) {
        sendJson(res, 400, { ok: false, error: sessionKey.error });
        return true;
      }
      const runId = dispatchAgentHook({
        ...normalized.value,
        sessionKey: sessionKey.value,
        agentId: resolveHookTargetAgentId(hooksConfig, normalized.value.agentId),
      });
      sendJson(res, 202, { ok: true, runId });
      return true;
    }

    if (hooksConfig.mappings.length > 0) {
      try {
        const mapped = await applyHookMappings(hooksConfig.mappings, {
          payload: payload as Record<string, unknown>,
          headers,
          url,
          path: subPath,
        });
        if (mapped) {
          if (!mapped.ok) {
            sendJson(res, 400, { ok: false, error: mapped.error });
            return true;
          }
          if (mapped.action === null) {
            res.statusCode = 204;
            res.end();
            return true;
          }
          if (mapped.action.kind === "wake") {
            dispatchWakeHook({
              text: mapped.action.text,
              mode: mapped.action.mode,
            });
            sendJson(res, 200, { ok: true, mode: mapped.action.mode });
            return true;
          }
          const channel = resolveHookChannel(mapped.action.channel);
          if (!channel) {
            sendJson(res, 400, { ok: false, error: getHookChannelError() });
            return true;
          }
          if (!isHookAgentAllowed(hooksConfig, mapped.action.agentId)) {
            sendJson(res, 400, { ok: false, error: getHookAgentPolicyError() });
            return true;
          }
          const sessionKey = resolveHookSessionKey({
            hooksConfig,
            source: "mapping",
            sessionKey: mapped.action.sessionKey,
          });
          if (!sessionKey.ok) {
            sendJson(res, 400, { ok: false, error: sessionKey.error });
            return true;
          }
          const runId = dispatchAgentHook({
            message: mapped.action.message,
            name: mapped.action.name ?? "Hook",
            agentId: resolveHookTargetAgentId(hooksConfig, mapped.action.agentId),
            wakeMode: mapped.action.wakeMode,
            sessionKey: sessionKey.value,
            deliver: resolveHookDeliver(mapped.action.deliver),
            channel,
            to: mapped.action.to,
            model: mapped.action.model,
            thinking: mapped.action.thinking,
            timeoutSeconds: mapped.action.timeoutSeconds,
            allowUnsafeExternalContent: mapped.action.allowUnsafeExternalContent,
          });
          sendJson(res, 202, { ok: true, runId });
          return true;
        }
      } catch (err) {
        logHooks.warn(`hook mapping failed: ${String(err)}`);
        sendJson(res, 500, { ok: false, error: "hook mapping failed" });
        return true;
      }
    }

    res.statusCode = 404;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Not Found");
    return true;
  };
}







// The Traffic Cop (createGatewayHttpServer)

// Ye hmare system ka main HTTP Server (Router) hai.
  // Jab request aati hai, toh ye check karta hai:
// Kya ye request Slack se aayi hai? ➡️ handleSlackHttpRequest ko bhej do.
// Kya ye OpenAI/Claude ka format hai? ➡️ handleOpenAiHttpRequest ko do.
// Kya ye Webhook (custom API) call hai? ➡️ handleHooksRequest ko pakdao.
// Kya user UI dekhna chahta hai? ➡️ handleControlUiHttpRequest par route karo.
// Ye function khud koi logic run nahi karta, bas sahi request ko sahi department mein forward karta hai.
// ye function open claw ka heart hai jo sara traffic receive krta h.
export function createGatewayHttpServer(opts: {

  // Main server ko pata hona chahiye ki agar /canvas ki request aaye, toh usko kahan bhejna hai.
  canvasHost: CanvasHostHandler | null;

  // Yeh ek Set (unique list) hai jisme un saare clients ki details hain jo currently WebSocket se connected hain.
  // Agar server ko achanak band hona pade, toh usko pata hona chahiye ki kin-kin logo ko "Goodbye" bolna hai.
  clients: Set<GatewayWsClient>;

  // Yeh teen settings Control UI (Admin Dashboard) ke liye hain. aur uski initial state kya hogi (Root).
  
  controlUiEnabled: boolean;

  //  kis raste par chalega (BasePath),
  controlUiBasePath: string;

  // // Dashboard on hai ya nahi (Enabled)
  controlUiRoot?: ControlUiRootState;

  // Ek True/False switch jo batata hai ki kya is server ko OpenAI-compatible API endpoints (jaise /v1/chat/completions) expose karne hain.
  openAiChatCompletionsEnabled: boolean;

  openResponsesEnabled: boolean;
  openResponsesConfig?: import("../config/types.gateway.js").GatewayHttpResponsesConfig;

  strictTransportSecurityHeader?: string;
  handleHooksRequest: HooksRequestHandler;
  handlePluginRequest?: HooksRequestHandler;
  resolvedAuth: ResolvedGatewayAuth;
  /** Optional rate limiter for auth brute-force protection. */
  rateLimiter?: AuthRateLimiter;
  tlsOptions?: TlsOptions;
}): HttpServer {
  
  const {
    canvasHost,
    clients,
    controlUiEnabled,
    controlUiBasePath,
    controlUiRoot,
    openAiChatCompletionsEnabled,
    openResponsesEnabled,
    openResponsesConfig,
    strictTransportSecurityHeader,
    handleHooksRequest,
    handlePluginRequest,
    resolvedAuth,
    rateLimiter,
  } = opts;


  // ye function config mein check krega ki kya hmare pass SSL/TLS certificates(encryption keys) hain? agar hain toh ek secure HTTPS server bnao, agr nhi hain toh ek normal HTTP server bnao.
  // node.js mein createHttpServer aur createHttpsServer functions built in hotey hain, toh ye function unn built in functions ko use krke, iske pass aane wali sari requests ko handleRequest naame k manager k pass bhej dega.
  const httpServer: HttpServer = opts.tlsOptions

    // Agr server k pass SSL/TLS certificate hain, Toh ek secure HTTPS server banao. 
    // Usme certificates (`opts.tlsOptions`) daalo aur ek function pass karo jo har aane wali request ko `handleRequest` ke paas bhej de.
    // Jab internet par data (jaise AI ki chat ya passwords) travel karta hai, toh usko encrypt (code bhasha mein convert) karna padta hai taaki raste mein koi hacker usko padh na sake. 
    // HTTPS yahi kaam karta hai. 
    // toh ye function Node.js ka `https` module `createHttpsServer` call karta hai. 
    // Yeh pehla parameter security keys leta hai aur doosra parameter ek callback function leta hai jo har request aane par trigger hoga. 
    ? createHttpsServer(opts.tlsOptions, (req, res) => {
        void handleRequest(req, res);
      })
      
      // agr server k pass SSL/TLS certificate nhi h toh ek normal, unsecured HTTP server banao aur wahi same handleRequest manager ko saari requests pass kar do.
      // Development (Dev mode) mein ya jab server kisi internal safe network (jaise VPN ya Tailscale) pe chal raha ho, tab certificates set up karna sar-dard hota hai aur zaroori bhi nahi hota. Tab normal HTTP server chalaya jata hai.
    : createHttpServer((req, res) => {
        void handleRequest(req, res);
      });

  
  // ye toh hmara ek request handler function ho gya, req hmari incoming request h, res hmara response h jo hum bhejengey.
  // server pr jo bhi request hit kregi wo yhi pass krdi jayegi, handleRequest function ko.
  async function handleRequest(req: IncomingMessage, res: ServerResponse) {

    // ab chaliye dekhtey hain ye block of code humne kyu add kiya h. jb browser (client), server se response leta hai, toh ek risk ho skta h, ki jo browser h wo insecure behave kr skta h ek toh aur dusra, attackers beech m data modify kr skte h jo server se aa rha h. 
    // isliye server ko, browser ko rules btane pdtey h, ki tum kaise behave krogey. aur ye rules http headers k thru bheje jate h.
    // ye ek helper function h jo repsonse m security headers add kr rha h.
    // kyu? taki browsers secure tareeke se response handle kr skein.
    // production systems n security headers compulsory hotey h.
    setDefaultSecurityHeaders(res, {
      strictTransportSecurity: strictTransportSecurityHeader,
    });

    // Ye code check karta hai ki request WebSocket upgrade ki hai ya nahi — agar hai, to usse ignore karta hai kyunki WebSocket handling kisi aur system (ws library) ke through hoti hai.
    // Sabse Badi Wajah: Normal HTTP request ek "Phone Call" jaisi hoti hai — Aapne call kiya, baat ki, aur phone kaat diya (Connection Closed). Par WebSocket ek "Walkie-Talkie" jaisa hota hai — Connection hamesha on rehta hai. 
    // Agar HTTP handler ne is request ko touch kar liya ya respond kar diya, toh network pipe band ho jayega aur WebSocket ban hi nahi payega.
    // Jab yeh function return karta hai, toh pichhe baitha hua server.on('upgrade', ...) event jag jata hai, jo is raw connection ko pakad kar pakka WebSocket bana deta hai.
    // Don't interfere with WebSocket upgrades; ws handles the 'upgrade' event.
    if (String(req.headers.upgrade ?? "").toLowerCase() === "websocket") {
      return;
    }

    // Jo saari requests upar se filter hokar aayi hain (chahe HTTP ho ya HTTPS), woh sabse pehle is try block se takrati hain.
    try {
      
      // aap dekh sktey ho ki yha pr developer ne config variables ko file k top pr rkhne ki jagah, Usne isko request aane ke andar rakha hai. 
      // Iska matlab hai ki agar admin, server chalte waqt config file mein koi change karta hai (jaise naya password set karna), toh server ko restart kiye bina hi agli request mein woh naye rules apply ho jayenge! 
      // Isey Hot-Reloading kehte hain.
      const configSnapshot = loadConfig();

      // ab yha pr hum config se do cheezein nikal rahe hain: 
      // 1) Kis-kis (Proxy/Load Balancer) par bharosa kiya ja sakta hai. 
      // 2) Kya proxy na hone par original IP ka andaza (fallback) lagana allowed hai?
      // toh isko aise smjho ki Jab hmara server Cloudflare ya AWS ke peeche hota hai, toh har request ka IP "Cloudflare ka IP" dikhta hai, asli user ka nahi. 
      // Asli IP `X-Forwarded-For` header mein chup ke aata hai. 
      // Par hacker bhi fake header bhej sakte hain. 
      // Isliye server ko pata hona chahiye ki kaunse IP sach mein Cloudflare ke hain (jinpe trust karna hai). |
      const trustedProxies = configSnapshot.gateway?.trustedProxies ?? [];
      const allowRealIpFallback = configSnapshot.gateway?.allowRealIpFallback === true;
      


      // Yeh line incoming URL ko ek special function `normalizeCanvasScopedUrl` ke through pass kar rahi hai. 
      // Yeh function ek kachre wale URL ko leta hai, usko dho-poch kar saaf karta hai, hacker attacks ko detect karta hai, aur ekdum clean structured data baahar nikal kar Gateway server ko de deta hai taaki server aaram se apna kaam kar sake!
      // Ek baat aur ki, Node.js mein req.url ki value hamesha sirf rasta (path) aur query hoti hai, jaise /canvas/app.js?id=1. 
      // Isme kabhi bhi aage ka http://www.domain.com nahi hota. Asli base URL (Domain/IP) humein req.url mein nahi, balki request ke lifafe yani req.headers.host mein milta hai.
      const scopedCanvas = normalizeCanvasScopedUrl(req.url ?? "/");
      
      // ab dekhtey hain ki ye wala block kya kr rha h. 
      // Internet se aane wala koi bhi data (jaise URL) safe nahi hota. Hacker kuch bhi type kar sakta hai.
      // Server ko apna kaam karne se pehle ensure karna padta hai ki jo URL aaya hai, kya uska format (shape) waisa hi hai jaisa humne design kiya tha? 
      // Agar shape bigda hua hai, toh usko "Malformed" kehte hain.
      // Agar URL malformed hai, toh server ko yeh nahi sochna chahiye ki "Shayad iska matlab yeh hoga". 
      // Server ko seedha connection kaat dena chahiye.
      // Jab tum connection kaat-te ho, toh hacker ko asli wajah mat batao (jaise: "Aapne URL mein double slash laga diya"). Sirf ek generic message do: "Aapko permission nahi hai (Unauthorized)".
      if (scopedCanvas.malformedScopedPath) {

        // Yeh line client (hacker ya user) ko ek Error Message bhej rahi hai jisme likha hai "unauthorized" (tumhe entry nahi milegi).
        sendGatewayAuthFailure(res, { ok: false, reason: "unauthorized" });

        // Execution ko yahin par turant rok dena.
        return;
      }
      

      // ab rewritten url k andar kya hoga isko example se dekhtey h.
      // manlo hmare dost ne browser mein yeh secret link paste kiya:
      // 👉 /__openclaw__/cap/VIP-TOKEN-999/profile/settings
      // toh ab server kya krega, Server isko ek naye, standard web format mein convert kr deta hai.
      // 👉 "/profile/settings?oc_cap=VIP-TOKEN-999" --> yhi h hmara rewritten url, aur aisa kyu hota h
      // Agar tum dhyaan se dekho, toh pehle Token (path) ke beech mein fasa hua tha (.../cap/TOKEN/profile...).
      // Aage aane wala jo UI server hai (maan lo React ya Next.js), usko page load karna hai. 
      // Agar tum usko /__openclaw__/cap/VIP-TOKEN-999/profile/settings doge, toh woh bolega: "Bhai, mere paas is naam ka koi folder ya page nahi hai! 404 Not Found."
      // Par jab tum usko rewrittenUrl yani /profile/settings?oc_cap=VIP-TOKEN-999 doge, toh UI server turant samajh jayega:
      // Path: "Mujhe /profile/settings wala page dikhana hai."
      // Query Parameter (?oc_cap=...): "Aur load hote waqt mujhe check karna hai ki user ke paas VIP-TOKEN-999 ki permission hai ya nahi."
      if (scopedCanvas.rewrittenUrl) {

        // Nayi value ko purane variable (req.url) ke upar overwrite kar deta hai.
        req.url = scopedCanvas.rewrittenUrl;
      }
      
      // ye line kya kregi, ye line naye/purane req.url ko leti hai, usko URL padhne wali machine (new URL) mein daalti hai, aur usme se sirf .pathname (raasta) nikal kar requestPath variable mein save kar leti hai.
      // req.url ke andar raaste ke saath-saath extra baggage bhi hota hai (jaise ?oc_cap=secret123 ya ?theme=dark). Agar hum is poore ko match karenge toh server file nahi dhoondh payega. Server ko strictly sirf room number (path) chahiye hota hai.
      const requestPath = new URL(req.url ?? "/", "http://localhost").pathname;
      

      // ✅ Scenario A (Webhook Request Aayi):
      // Request aayi /api/webhooks/github se.
      // handleHooksRequest ne URL dekha aur bola: "Haan, yeh mera department hai!"
      // Usne webhook process kiya (Wake/Agent hook chalaya) aur bola return true;.
      // Tumhari if condition ko true mil gaya. Uske andar ka return; execute ho gaya.
      // Result: Main function (Gateway) wahin ruk gaya, taaki woh aage jaakar galti se is webhook ko Canvas UI samajh kar error na de de. (Isey Early Exit pattern kehte hain).

      // ❌ Scenario B (Normal Canvas Request Aayi):
      // Request aayi /canvas/app.js se.
      // handleHooksRequest ne URL dekha aur bola: "Yeh webhook nahi hai, mera isse koi lena-dena nahi."
      // Usne chup-chap return false; de diya.
      // Tumhari if condition fail ho gayi.
      // Result: Code us if block ko chhod kar niche chala gaya, jahan tumhara main Gateway function baaki ka kaam (Canvas serve karna) aaram se karta rahega.
      if (await handleHooksRequest(req, res)) {
        return;
      }
      
      // Main server aane wali request ko is "Tools Manager" wale function ke paas bhejta hai aur poochta hai: "Bhai, kya yeh request tumhare department (Tools invoke) ki hai?"
      // Khali haath nahi bhejta. Server us manager ko request ke saath-saath uske security guards (rateLimiter) aur password checker (auth) bhi deta hai, taaki manager khud check kar sake ki aadmi legit hai ya nahi.
      // Agar woh request sach mein Tools API ki thi, toh manager usko handle kar lega (chahe paas kare ya reject kare) aur wapas true bhej dega. true milte hi yeh if block chal jayega aur return ho jayega. Matlab main server yahin apna kaam rok dega, aage ki lines (jaise Canvas ya Webhooks check karna) nahi padhega.
      // Agar request Tools API ki nahi thi, toh manager bolega false. if block fail ho jayega, aur server chup-chaap aage badh jayega check karne ki "Shayad yeh kisi aur department ki request hogi."
      if (
        await handleToolsInvokeHttpRequest(req, res, {
          auth: resolvedAuth,
          trustedProxies,
          allowRealIpFallback,
          rateLimiter,
        })
      ) {
        return;
      }
      
      // Yeh block check karta hai ki aane wali request kahin Slack (Messaging App) ki taraf se toh nahi aayi hai? 
      // Agar haan, toh usko "Slack Department" handle kar lega aur main server apna kaam yahin rok dega.
      if (await handleSlackHttpRequest(req, res)) {
        return;
      }
      
      // OpenClaw sirf apne in-built features par dependent nahi hai. Agar kal ko koi developer apna custom feature (Plugin) banakar isme daalna chahe, toh yeh block us plugin ko internet ki requests sunne ki power deta hai.
      // Yeh block check karta hai ki kya aane wali request kisi "Custom Plugin" ke liye hai? Agar haan, toh usko handle karta hai, par core "Channels" ko access karne se pehle ek strict ID/Password check bhi karta hai.
      if (handlePluginRequest) {
        // Channel HTTP endpoints are gateway-auth protected by default.
        // Non-channel plugin routes remain plugin-owned and must enforce
        // their own auth when exposing sensitive functionality.
        if (requestPath === "/api/channels" || requestPath.startsWith("/api/channels/")) {
      
          const token = getBearerToken(req);
      
          const authResult = await authorizeHttpGatewayConnect({
            auth: resolvedAuth,
            connectAuth: token ? { token, password: token } : null,
            req,
            trustedProxies,
            allowRealIpFallback,
            rateLimiter,
          });
      
          if (!authResult.ok) {
            sendGatewayAuthFailure(res, authResult);
            return;
          }
        }
      
        if (await handlePluginRequest(req, res)) {
          return;
        }
      }
      
      if (openResponsesEnabled) {
        if (
          await handleOpenResponsesHttpRequest(req, res, {
            auth: resolvedAuth,
            config: openResponsesConfig,
            trustedProxies,
            allowRealIpFallback,
            rateLimiter,
          })
        ) {
          return;
        }
      }
      
      if (openAiChatCompletionsEnabled) {
        if (
          await handleOpenAiHttpRequest(req, res, {
            auth: resolvedAuth,
            trustedProxies,
            allowRealIpFallback,
            rateLimiter,
          })
        ) {
          return;
        }
      }
      
      if (canvasHost) {
        if (isCanvasPath(requestPath)) {
          const ok = await authorizeCanvasRequest({
            req,
            auth: resolvedAuth,
            trustedProxies,
            allowRealIpFallback,
            clients,
            canvasCapability: scopedCanvas.capability,
            malformedScopedPath: scopedCanvas.malformedScopedPath,
            rateLimiter,
          });
      
          if (!ok.ok) {
            sendGatewayAuthFailure(res, ok);
            return;
          }
        }
      
        if (await handleA2uiHttpRequest(req, res)) {
          return;
        }
      
        if (await canvasHost.handleHttpRequest(req, res)) {
          return;
        }
      }
      
      if (controlUiEnabled) {
        if (
          handleControlUiAvatarRequest(req, res, {
            basePath: controlUiBasePath,
            resolveAvatar: (agentId) => resolveAgentAvatar(configSnapshot, agentId),
          })
        ) {
          return;
        }
      
        if (
          handleControlUiHttpRequest(req, res, {
            basePath: controlUiBasePath,
            config: configSnapshot,
            root: controlUiRoot,
          })
        ) {
          return;
        }
      }

      res.statusCode = 404;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("Not Found");
    } catch {
      res.statusCode = 500;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("Internal Server Error");
    }
  }

  return httpServer;
}






// HTTP requests one-way hoti hain (Client ne pucha, server ne bataya). Par Xorthax jaise AI agent platform mein real-time baatcheet zaroori hai.
// Ye function aam HTTP request ko pakadta hai aur usko ek WebSocket (wss) mein "Upgrade" kar deta hai.
// Iske baad server aur client ke beech ek khuli line ban jaati hai jisse data dono taraf bina delay ke beh sakta hai.
export function attachGatewayUpgradeHandler(opts: {
  httpServer: HttpServer;
  wss: WebSocketServer;
  canvasHost: CanvasHostHandler | null;
  clients: Set<GatewayWsClient>;
  resolvedAuth: ResolvedGatewayAuth;
  /** Optional rate limiter for auth brute-force protection. */
  rateLimiter?: AuthRateLimiter;
}) {
  const { httpServer, wss, canvasHost, clients, resolvedAuth, rateLimiter } = opts;
  httpServer.on("upgrade", (req, socket, head) => {
    void (async () => {
      const scopedCanvas = normalizeCanvasScopedUrl(req.url ?? "/");
      if (scopedCanvas.malformedScopedPath) {
        writeUpgradeAuthFailure(socket, { ok: false, reason: "unauthorized" });
        socket.destroy();
        return;
      }
      if (scopedCanvas.rewrittenUrl) {
        req.url = scopedCanvas.rewrittenUrl;
      }
      if (canvasHost) {
        const url = new URL(req.url ?? "/", "http://localhost");
        if (url.pathname === CANVAS_WS_PATH) {
          const configSnapshot = loadConfig();
          const trustedProxies = configSnapshot.gateway?.trustedProxies ?? [];
          const allowRealIpFallback = configSnapshot.gateway?.allowRealIpFallback === true;
          const ok = await authorizeCanvasRequest({
            req,
            auth: resolvedAuth,
            trustedProxies,
            allowRealIpFallback,
            clients,
            canvasCapability: scopedCanvas.capability,
            malformedScopedPath: scopedCanvas.malformedScopedPath,
            rateLimiter,
          });
          if (!ok.ok) {
            writeUpgradeAuthFailure(socket, ok);
            socket.destroy();
            return;
          }
        }
        if (canvasHost.handleUpgrade(req, socket, head)) {
          return;
        }
      }
      wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit("connection", ws, req);
      });
    })().catch(() => {
      socket.destroy();
    });
  });
}
