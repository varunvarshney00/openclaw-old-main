// ye hmare poore backend ka "Grand Central Station" ya "Main API Gateway" hai.

// Jab bhi bahar ki duniya se, jaise (WhatsApp, Slack, Web UI, ya OpenAI) koi bhi request hmare server par aati hai, toh wo sabse pehle is file ke gate par knock krti hai.

import {
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

type SubsystemLogger = ReturnType<typeof createSubsystemLogger>;

const HOOK_AUTH_FAILURE_LIMIT = 20;
const HOOK_AUTH_FAILURE_WINDOW_MS = 60_000;

type HookDispatchers = {
  dispatchWakeHook: (value: { text: string; mode: "now" | "next-heartbeat" }) => void;
  dispatchAgentHook: (value: HookAgentDispatchPayload) => string;
};

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

function isCanvasPath(pathname: string): boolean {
  return (
    pathname === A2UI_PATH ||
    pathname.startsWith(`${A2UI_PATH}/`) ||
    pathname === CANVAS_HOST_PATH ||
    pathname.startsWith(`${CANVAS_HOST_PATH}/`) ||
    pathname === CANVAS_WS_PATH
  );
}

function isNodeWsClient(client: GatewayWsClient): boolean {
  if (client.connect.role === "node") {
    return true;
  }
  return normalizeGatewayClientMode(client.connect.client.mode) === GATEWAY_CLIENT_MODES.NODE;
}

function hasAuthorizedNodeWsClientForCanvasCapability(
  clients: Set<GatewayWsClient>,
  capability: string,
): boolean {
  const nowMs = Date.now();
  for (const client of clients) {
    if (!isNodeWsClient(client)) {
      continue;
    }
    if (!client.canvasCapability || !client.canvasCapabilityExpiresAtMs) {
      continue;
    }
    if (client.canvasCapabilityExpiresAtMs <= nowMs) {
      continue;
    }
    if (safeEqualSecret(client.canvasCapability, capability)) {
      // Sliding expiration while the connected node keeps using canvas.
      client.canvasCapabilityExpiresAtMs = nowMs + CANVAS_CAPABILITY_TTL_MS;
      return true;
    }
  }
  return false;
}

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

      
  async function handleRequest(req: IncomingMessage, res: ServerResponse) {
    setDefaultSecurityHeaders(res, {
      strictTransportSecurity: strictTransportSecurityHeader,
    });

    // Don't interfere with WebSocket upgrades; ws handles the 'upgrade' event.
    if (String(req.headers.upgrade ?? "").toLowerCase() === "websocket") {
      return;
    }

    try {
      const configSnapshot = loadConfig();
      const trustedProxies = configSnapshot.gateway?.trustedProxies ?? [];
      const allowRealIpFallback = configSnapshot.gateway?.allowRealIpFallback === true;
      const scopedCanvas = normalizeCanvasScopedUrl(req.url ?? "/");
      if (scopedCanvas.malformedScopedPath) {
        sendGatewayAuthFailure(res, { ok: false, reason: "unauthorized" });
        return;
      }
      if (scopedCanvas.rewrittenUrl) {
        req.url = scopedCanvas.rewrittenUrl;
      }
      const requestPath = new URL(req.url ?? "/", "http://localhost").pathname;
      if (await handleHooksRequest(req, res)) {
        return;
      }
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
      if (await handleSlackHttpRequest(req, res)) {
        return;
      }
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
