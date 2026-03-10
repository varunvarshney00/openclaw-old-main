// https://chatgpt.com/c/69aaeadc-9910-8324-9c59-ff3c74c3ca30
// https://gemini.google.com/app/b256d00eb7398690


// ye hmare project ka security guard hai. ye ek authentication and authorization module hai. typescript, nodejs, external networks (tailscale) aur proxies (nginx/cloudflare) ka dhyan rkha gya h. 
// manlo koi user ya frontend system hmare project(api/gateway) se connect hone ki koshish krega (chahe http request ho ya websocket), yeh file decide kregi ki "kya is user ko andar aane dena hai?" Yeh 
// token check karti hai, 
// password check karti hai, 
// rate-limiting (spam rokna) karti hai, 
// aur proxy headers verify karti hai.
// data flow kuch aisa hota : request (http) request aai -> uska ip address nikala -> Rate limiter check kiya (kya isne zyada attempts toh nahi kiye?) → Credentials (Token/Password/VPN) match kiye → Access Allowed ya Denied (Reason ke saath). 

import type { IncomingMessage } from "node:http";
// type ka matlab hai hum sirf iska "dhacha" (structure) laa rahe hain, execution ke time yeh code mein nahi jayega (TypeScript feature). { IncomingMessage } ek specific class hai jo HTTP request ke data ko hold karti hai. 
// from "node:http" NodeJS ka inbuilt network module hai.
// KYU HAI: Humari functions ko pata hona chahiye ki ek aane wali HTTP request dikhti kaisi hai.
// KAISE KAAM KARTA HAI: Jab bhi koi function IncomingMessage mangega, TypeScript check karega ki usme headers, url, etc. sahi se hain ya nahi.
// Example: Jaise bank form bharte waqt ek "Sample Form" hota hai dikhane ke liye, waise hi yeh type ek sample hai.

import type {
  GatewayAuthConfig,
  GatewayTailscaleMode,
  GatewayTrustedProxyConfig,
} from "../config/config.js";
// KYU HAI: Humare app ke pass passwords aur tokens kahan store hain, uski config settings yahan use hongi.

import { readTailscaleWhoisIdentity, type TailscaleWhoisIdentity } from "../infra/tailscale.js";
// KYU HAI: Tailscale ek private VPN/Mesh network hota hai. Agar user uske through aa raha hai, toh uski identity verify karne ke liye yeh chahiye.

import { safeEqualSecret } from "../security/secret-equal.js";
// KYA HAI: Yeh ek security function hai jo do passwords ya tokens ko compare karta hai.
// KYU HAI: ⚠️ Dhyan Do: Hum normal == se password check nahi karte kyunki usme "Timing Attack" (hackers time note karke password guess kar lete hain) ka risk hota hai. safeEqualSecret time-constant comparison karta hai.

import {
  AUTH_RATE_LIMIT_SCOPE_SHARED_SECRET,
  type AuthRateLimiter,
  type RateLimitCheckResult,
} from "./auth-rate-limit.js";
// KYA HAI: Rate limiting (spam rokne ka system) ke tools import kar rahe hain.
// KYU HAI: Agar koi hacker baar-baar galat password daal raha hai (Brute Force attack), toh usko block karne ke liye.

import { resolveGatewayCredentialsFromValues } from "./credentials.js";
import {
  isLocalishHost,
  isLoopbackAddress,
  isTrustedProxyAddress,
  resolveClientIp,
} from "./net.js";
// KYA HAI: Credentials nikalne ka aur network/IP address check karne (ki request localhost se aayi hai ya bahar se) ke helpers import kiye hain.

// jo hmara resolvedgatewayauthmode k types h wo ye 4 hain, ye sirf inhi 4 types ka ho skta h. mtlb user inn 4 tareekon se hi authenticate kr skta h, ya toh none, using a token, using a password, using a trusted-proxy.
export type ResolvedGatewayAuthMode = "none" | "token" | "password" | "trusted-proxy";

export type ResolvedGatewayAuthModeSource =
  | "override"
  | "config"
  | "password"
  | "token"
  | "default";

export type ResolvedGatewayAuth = {
  mode: ResolvedGatewayAuthMode;
  modeSource?: ResolvedGatewayAuthModeSource;
  token?: string;
  password?: string;
  allowTailscale: boolean;
  trustedProxy?: GatewayTrustedProxyConfig;
};

export type GatewayAuthResult = {
  ok: boolean;
  method?: "none" | "token" | "password" | "tailscale" | "device-token" | "trusted-proxy";
  user?: string;
  reason?: string;
  /** Present when the request was blocked by the rate limiter. */
  rateLimited?: boolean;
  /** Milliseconds the client should wait before retrying (when rate-limited). */
  retryAfterMs?: number;
};

type ConnectAuth = {
  token?: string;
  password?: string;
};

export type GatewayAuthSurface = "http" | "ws-control-ui";

export type AuthorizeGatewayConnectParams = {
  auth: ResolvedGatewayAuth;
  connectAuth?: ConnectAuth | null;
  req?: IncomingMessage;
  trustedProxies?: string[];
  tailscaleWhois?: TailscaleWhoisLookup;
  /**
   * Explicit auth surface. HTTP keeps Tailscale forwarded-header auth disabled.
   * WS Control UI enables it intentionally for tokenless trusted-host login.
   */
  authSurface?: GatewayAuthSurface;
  /** Optional rate limiter instance; when provided, failed attempts are tracked per IP. */
  rateLimiter?: AuthRateLimiter;
  /** Client IP used for rate-limit tracking. Falls back to proxy-aware request IP resolution. */
  clientIp?: string;
  /** Optional limiter scope; defaults to shared-secret auth scope. */
  rateLimitScope?: string;
  /** Trust X-Real-IP only when explicitly enabled. */
  allowRealIpFallback?: boolean;
};

type TailscaleUser = {
  login: string;
  name: string;
  profilePic?: string;
};

type TailscaleWhoisLookup = (ip: string) => Promise<TailscaleWhoisIdentity | null>;

// trim() -> // Ye string ke start aur end ke extra spaces hata deta hai.
// 
function normalizeLogin(login: string): string {
  return login.trim().toLowerCase();
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

const TAILSCALE_TRUSTED_PROXIES = ["127.0.0.1", "::1"] as const;

function resolveTailscaleClientIp(req?: IncomingMessage): string | undefined {
  if (!req) {
    return undefined;
  }
  return resolveClientIp({
    remoteAddr: req.socket?.remoteAddress ?? "",
    forwardedFor: headerValue(req.headers?.["x-forwarded-for"]),
    trustedProxies: [...TAILSCALE_TRUSTED_PROXIES],
  });
}

function resolveRequestClientIp(
  req?: IncomingMessage,
  trustedProxies?: string[],
  allowRealIpFallback = false,
): string | undefined {
  if (!req) {
    return undefined;
  }
  return resolveClientIp({
    remoteAddr: req.socket?.remoteAddress ?? "",
    forwardedFor: headerValue(req.headers?.["x-forwarded-for"]),
    realIp: headerValue(req.headers?.["x-real-ip"]),
    trustedProxies,
    allowRealIpFallback,
  });
}

export function isLocalDirectRequest(
  req?: IncomingMessage,
  trustedProxies?: string[],
  allowRealIpFallback = false,
): boolean {
  if (!req) {
    return false;
  }
  const clientIp = resolveRequestClientIp(req, trustedProxies, allowRealIpFallback) ?? "";
  if (!isLoopbackAddress(clientIp)) {
    return false;
  }

  const hasForwarded = Boolean(
    req.headers?.["x-forwarded-for"] ||
    req.headers?.["x-real-ip"] ||
    req.headers?.["x-forwarded-host"],
  );

  const remoteIsTrustedProxy = isTrustedProxyAddress(req.socket?.remoteAddress, trustedProxies);
  return isLocalishHost(req.headers?.host) && (!hasForwarded || remoteIsTrustedProxy);
}

function getTailscaleUser(req?: IncomingMessage): TailscaleUser | null {
  if (!req) {
    return null;
  }
  const login = req.headers["tailscale-user-login"];
  if (typeof login !== "string" || !login.trim()) {
    return null;
  }
  const nameRaw = req.headers["tailscale-user-name"];
  const profilePic = req.headers["tailscale-user-profile-pic"];
  const name = typeof nameRaw === "string" && nameRaw.trim() ? nameRaw.trim() : login.trim();
  return {
    login: login.trim(),
    name,
    profilePic: typeof profilePic === "string" && profilePic.trim() ? profilePic.trim() : undefined,
  };
}

function hasTailscaleProxyHeaders(req?: IncomingMessage): boolean {
  if (!req) {
    return false;
  }
  return Boolean(
    req.headers["x-forwarded-for"] &&
    req.headers["x-forwarded-proto"] &&
    req.headers["x-forwarded-host"],
  );
}

function isTailscaleProxyRequest(req?: IncomingMessage): boolean {
  if (!req) {
    return false;
  }
  return isLoopbackAddress(req.socket?.remoteAddress) && hasTailscaleProxyHeaders(req);
}

async function resolveVerifiedTailscaleUser(params: {
  req?: IncomingMessage;
  tailscaleWhois: TailscaleWhoisLookup;
}): Promise<{ ok: true; user: TailscaleUser } | { ok: false; reason: string }> {
  const { req, tailscaleWhois } = params;
  const tailscaleUser = getTailscaleUser(req);
  if (!tailscaleUser) {
    return { ok: false, reason: "tailscale_user_missing" };
  }
  if (!isTailscaleProxyRequest(req)) {
    return { ok: false, reason: "tailscale_proxy_missing" };
  }
  const clientIp = resolveTailscaleClientIp(req);
  if (!clientIp) {
    return { ok: false, reason: "tailscale_whois_failed" };
  }
  const whois = await tailscaleWhois(clientIp);
  if (!whois?.login) {
    return { ok: false, reason: "tailscale_whois_failed" };
  }
  if (normalizeLogin(whois.login) !== normalizeLogin(tailscaleUser.login)) {
    return { ok: false, reason: "tailscale_user_mismatch" };
  }
  return {
    ok: true,
    user: {
      login: whois.login,
      name: whois.name ?? tailscaleUser.name,
      profilePic: tailscaleUser.profilePic,
    },
  };
}

export function resolveGatewayAuth(params: {
  authConfig?: GatewayAuthConfig | null;
  authOverride?: GatewayAuthConfig | null;
  env?: NodeJS.ProcessEnv;
  tailscaleMode?: GatewayTailscaleMode;
}): ResolvedGatewayAuth {
  const baseAuthConfig = params.authConfig ?? {};
  const authOverride = params.authOverride ?? undefined;
  const authConfig: GatewayAuthConfig = { ...baseAuthConfig };
  if (authOverride) {
    if (authOverride.mode !== undefined) {
      authConfig.mode = authOverride.mode;
    }
    if (authOverride.token !== undefined) {
      authConfig.token = authOverride.token;
    }
    if (authOverride.password !== undefined) {
      authConfig.password = authOverride.password;
    }
    if (authOverride.allowTailscale !== undefined) {
      authConfig.allowTailscale = authOverride.allowTailscale;
    }
    if (authOverride.rateLimit !== undefined) {
      authConfig.rateLimit = authOverride.rateLimit;
    }
    if (authOverride.trustedProxy !== undefined) {
      authConfig.trustedProxy = authOverride.trustedProxy;
    }
  }
  const env = params.env ?? process.env;
  const resolvedCredentials = resolveGatewayCredentialsFromValues({
    configToken: authConfig.token,
    configPassword: authConfig.password,
    env,
    includeLegacyEnv: false,
    tokenPrecedence: "config-first",
    passwordPrecedence: "config-first",
  });
  const token = resolvedCredentials.token;
  const password = resolvedCredentials.password;
  const trustedProxy = authConfig.trustedProxy;

  let mode: ResolvedGatewayAuth["mode"];
  let modeSource: ResolvedGatewayAuth["modeSource"];
  if (authOverride?.mode !== undefined) {
    mode = authOverride.mode;
    modeSource = "override";
  } else if (authConfig.mode) {
    mode = authConfig.mode;
    modeSource = "config";
  } else if (password) {
    mode = "password";
    modeSource = "password";
  } else if (token) {
    mode = "token";
    modeSource = "token";
  } else {
    mode = "token";
    modeSource = "default";
  }

  const allowTailscale =
    authConfig.allowTailscale ??
    (params.tailscaleMode === "serve" && mode !== "password" && mode !== "trusted-proxy");

  return {
    mode,
    modeSource,
    token,
    password,
    allowTailscale,
    trustedProxy,
  };
}

////////////////////////////////////////////////////

// Jab server start hota hai, toh request aane ka wait karne ke bajaye, yeh function pehle hi check kar leta hai ki admin/developer ne config file mein koi bevakoofi toh nahi ki hai. Agar setting galat hai, toh yeh server ko wahin crash kar dega taaki baad mein production mein aafat na aaye.
export function assertGatewayAuthConfigured(auth: ResolvedGatewayAuth): void {
  if (auth.mode === "token" && !auth.token) {
    
    // Agar admin ne token nahi diya, par VPN login on rakha hai, toh hum server ko crash nahi karenge kyunki log kam se kam VPN ke through toh andar aa hi sakte hain.
    if (auth.allowTailscale) {
      return;
    }

    throw new Error(
      "gateway auth mode is token, but no token was configured (set gateway.auth.token or OPENCLAW_GATEWAY_TOKEN)",
    );
  }

  if (auth.mode === "password" && !auth.password) {
    throw new Error("gateway auth mode is password, but no password was configured");
  }

  if (auth.mode === "trusted-proxy") {
    if (!auth.trustedProxy) {
      throw new Error(
        "gateway auth mode is trusted-proxy, but no trustedProxy config was provided (set gateway.auth.trustedProxy)",
      );
    }
    if (!auth.trustedProxy.userHeader || auth.trustedProxy.userHeader.trim() === "") {
      throw new Error(
        "gateway auth mode is trusted-proxy, but trustedProxy.userHeader is empty (set gateway.auth.trustedProxy.userHeader)",
      );
    }
  }
}

///////////////////////////////////////////////////

/**
 * Check if the request came from a trusted proxy and extract user identity.
 * Returns the user identity if valid, or null with a reason if not.
 */
function authorizeTrustedProxy(params: {
  req?: IncomingMessage;
  trustedProxies?: string[];
  trustedProxyConfig: GatewayTrustedProxyConfig;
}): { user: string } | { reason: string } {
  const { req, trustedProxies, trustedProxyConfig } = params;

  if (!req) {
    return { reason: "trusted_proxy_no_request" };
  }

  const remoteAddr = req.socket?.remoteAddress;
  if (!remoteAddr || !isTrustedProxyAddress(remoteAddr, trustedProxies)) {
    return { reason: "trusted_proxy_untrusted_source" };
  }

  const requiredHeaders = trustedProxyConfig.requiredHeaders ?? [];
  for (const header of requiredHeaders) {
    const value = headerValue(req.headers[header.toLowerCase()]);
    if (!value || value.trim() === "") {
      return { reason: `trusted_proxy_missing_header_${header}` };
    }
  }

  const userHeaderValue = headerValue(req.headers[trustedProxyConfig.userHeader.toLowerCase()]);
  if (!userHeaderValue || userHeaderValue.trim() === "") {
    return { reason: "trusted_proxy_user_missing" };
  }

  const user = userHeaderValue.trim();

  const allowUsers = trustedProxyConfig.allowUsers ?? [];
  if (allowUsers.length > 0 && !allowUsers.includes(user)) {
    return { reason: "trusted_proxy_user_not_allowed" };
  }

  return { user };
}

function shouldAllowTailscaleHeaderAuth(authSurface: GatewayAuthSurface): boolean {
  return authSurface === "ws-control-ui";
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////

// ye hmara main function hai, chief security officer yhi h hmara. yha hmare gateway ko decide krna h ki incoming jo request h usko system k andar allow krna h ya nhi.
// Is decision ke liye system ko kuch cheezein pata honi chahiye:
// Authentication config kya hai?
// User ne kya credentials bheje?
// Request kis IP se aayi?
// Kya trusted proxy use hua?
// Kya Tailscale VPN se request aayi?
// Isliye function ka input = request + auth info
// Aur output = allow/deny result
export default async function authorizeGatewayConnect(
  params: AuthorizeGatewayConnectParams,
): Promise<GatewayAuthResult> 
// ye hmara function declaration. function ka kaam h take request + auth data -> check security rules -> return result. params: AuthorizeGatewayConnectParams, Ye ek object hai jisme request related data hai.
// promise ek container hota h future result k liye, promise ki 3 states hoti h pending, fulfilled, rejected. Promise<GatewayAuthResult> iska mtlb h function future m GatewayAuthResult result return krega.
// params: AuthorizeGatewayConnectParams, params ek object hai jiska structure AuthorizeGatewayConnectParams type follow karega

{
  // yha pr humne params se data extract kr liya, isko object destructuring boltey hain.
  const { auth, connectAuth, req, trustedProxies } = params;
  // params = {
  //   auth: { mode: "token", token: "abc123" }, decide karne ke liye kaunsa auth method use karna hai
  //   connectAuth: { token: "abc123" }, Yeh client ne jo credentials bheje hain, client ka token compare karne ke liye
  //   req: IncomingMessageObject, Yeh Node.js HTTP request object hai. Isme request ka sara data hota hai.
  //   trustedProxies: ["127.0.0.1"] kin proxies pe trust karna hai
  // }

//Example architecture:
// Client
//    ↓
// Cloudflare
//    ↓
// Nginx
//    ↓
// Node Server

// Function inside:
// extract params
// ↓
// check rate limiter
// ↓
// check token
// ↓
// return result

  const tailscaleWhois = params.tailscaleWhois ?? readTailscaleWhoisIdentity;
  // TailscaleWhoisLookup kya hai
  // Ye ek function type hai.
  // ye function IP lega
  // aur Tailscale user identity return karega

  // readTailscaleWhoisIdentity kya hai
  // Ye default function hai jo Tailscale se user identity nikalta hai.

  // Tailscale consumer VPN nahi hai.
  // Ye hai:
  // Zero Trust Private Network
  // Simple language me:
  // Company ka private internet
  // Example company network:
  // Laptop (Employee)
  //        │
  //        ▼
  // Tailscale Network
  //        │
  //        ▼
  // Internal Servers

  // Yaha sab devices ek private mesh network me hote hain.
  // Tailscale Ka Special Feature
  // Normal VPN:
  // identity hidden
  // Tailscale:
  // identity verified

  // Jab request aati hai Tailscale network se:
  //  client IP = 100.x.x.x
  // Server run karta hai:
  //  tailscale whois 100.101.102.103
  // Result:
  //  User: varun@company.com
  //  Device: varun-laptop
  // Matlab:
  //  IP → user identity
  // tailscale whois 100.101.102.103

  // Flow:
  // Request
  //    │
  //    ▼
  // Check tailscale headers
  //    │
  //    ▼
  // Get client IP
  //    │
  //    ▼
  // tailscaleWhois(ip)
  //    │
  //    ▼
  // Get user identity
  //    │
  //    ▼
  // Allow request

  const authSurface = params.authSurface ?? "http";
  // Request kis interface se aayi hai (HTTP ya WebSocket UI). Agar specify nahi hua to default HTTP assume karo.
  // Security systems me surface ka matlab hota hai:
  // System ke kis entry point se request aa rahi hai
  // Gateway Server
  //    │
  //    ├── REST API
  //    ├── WebSocket UI
  //    └── CLI connections
  // Har entry point ko bolte hain:
  // authentication surface
  // Example surfaces:
  // http
  // ws-control-ui
  // REST API → normal HTTP requests
  // WebSocket UI → real-time persistent connection
  // CLI → terminal tool jo gateway se connect karta hai

  const allowTailscaleHeaderAuth = shouldAllowTailscaleHeaderAuth(authSurface);
  // Check karo kya current request surface par Tailscale header-based authentication allow hai ya nahi.
  // Matlab function bas ye check karta hai:
  // agar surface = ws-control-ui
  //    → true
  // warna
  //    → false

  const localDirect = isLocalDirectRequest(
    req,
    trustedProxies,
    params.allowRealIpFallback === true,
  );
  // Check karo kya request genuinely localhost se direct aayi hai
  // (proxy spoofing ke bina)
  // Ye variable later auth decisions me use hota hai.
  // jb koi request server pr aati h normally, nodejs k, nodejs ko sirf req.socket.remoteAddress ye dikhta h. lakin modern infrastructure m request direct client se nhi aati. request -> cloudflare -> nginx -> node gateway, toh server ko remoteAddress nginx ka dikhta h, na ki real user ka. Isliye proxies ek header bhejte hain: x-forwarded-for: 203.10.2.5 Jisse server ko real client IP pata chale. 
  // Problem: Ye headers fake bhi ho sakte hain, Attack example:
    // POST /api
    // x-forwarded-for: 127.0.0.1
  // Agar server blindly trust kare:
    // clientIp = 127.0.0.1
  // To system sochega:
    // ye localhost request hai
    // Aur attacker security bypass kar sakta hai.
  // Isliye rule:
    // Forwarded headers tabhi trust karo
    // jab request trusted proxy se aaye
  // Yahi kaam karta hai:
    // trustedProxies


  // Yeh block trusted proxy ke through authenticated user ko verify karta hai aur agar proxy trusted ho aur header valid ho toh user ko gateway access de deta hai.
  if (auth.mode === "trusted-proxy") {
    if (!auth.trustedProxy) {
      return { ok: false, reason: "trusted_proxy_config_missing" };
    }
    if (!trustedProxies || trustedProxies.length === 0) {
      return { ok: false, reason: "trusted_proxy_no_proxies_configured" };
    }

    const result = authorizeTrustedProxy({
      req,
      trustedProxies,
      trustedProxyConfig: auth.trustedProxy,
    });

    if ("user" in result) {
      return { ok: true, method: "trusted-proxy", user: result.user };
    }
    return { ok: false, reason: result.reason };
  }

  // Agar authentication disabled hai to request ko bina kisi verification ke allow kar do.
  if (auth.mode === "none") {
    return { ok: true, method: "none" };
  }

  
  const limiter = params.rateLimiter;
  const ip =
    params.clientIp ??
    resolveRequestClientIp(req, trustedProxies, params.allowRealIpFallback === true) ??
    req?.socket?.remoteAddress;
  const rateLimitScope = params.rateLimitScope ?? AUTH_RATE_LIMIT_SCOPE_SHARED_SECRET;
  // Ye code block rate limiting ke liye required information prepare karta hai:
  // kaunsa limiter use hoga
  // client ka real IP kya hai
  // kis scope par rate limit apply hogi

  if (limiter) {
    const rlCheck: RateLimitCheckResult = limiter.check(ip, rateLimitScope);
    if (!rlCheck.allowed) {
      return {
        ok: false,
        reason: "rate_limited",
        rateLimited: true,
        retryAfterMs: rlCheck.retryAfterMs,
      };
    }
  }
  // Khas taur par jab tum kisi aisi chiz ka system design karte ho jahan security aur paise ka flow hota hai (jaise Payment Gateways), toh Rate Limiting ek non-negotiable feature hota hai. Agar checkout endpoint par rate limiter nahi hoga, toh malicious actors fake credit cards test karne ke liye tumhari API par script chala denge, jisse tumhara payment provider tumhe block kar dega. Yeh code usi aafat ko API entry point par hi kill kar raha ha

  if (allowTailscaleHeaderAuth && auth.allowTailscale && !localDirect) {
    const tailscaleCheck = await resolveVerifiedTailscaleUser({
      req,
      tailscaleWhois,
    });
    if (tailscaleCheck.ok) {
      limiter?.reset(ip, rateLimitScope);
      return {
        ok: true,
        method: "tailscale",
        user: tailscaleCheck.user.login,
      };
    }
  }

  // yeh block tumhare system ka "Token Authentication" engine hai. Agar user VIP proxy se nahi aaya, aur VPN (Tailscale) bhi use nahi kar raha, toh usko andar aane ke liye ek Secret Token (API Key jaisa) dikhana padega. Yeh code usi token ko verify karta hai.
  // Yeh poora block ek secure, production-ready Token Validator hai. Yeh sirf token match nahi karta, balki edge cases (jaise server mein hi token na hona) ko handle karta hai. Sabse zaroori baat, yeh har galat koshish par Rate Limiter ko batata hai ki "Is user ko flag karo" (Record Failure), jisse Brute-Force attacks namumkin ho jate hain. Aur security ko top-tier rakhne ke liye yeh Timing Attacks se bachne wala safeEqualSecret comparison use karta hai. Sahi token milne par hi yeh saare flags hata kar access allow karta hai.
  if (auth.mode === "token") {
    if (!auth.token) {
      return { ok: false, reason: "token_missing_config" };
    }
    if (!connectAuth?.token) {
      limiter?.recordFailure(ip, rateLimitScope);
      return { ok: false, reason: "token_missing" };
    }
    if (!safeEqualSecret(connectAuth.token, auth.token)) {
      limiter?.recordFailure(ip, rateLimitScope);
      return { ok: false, reason: "token_mismatch" };
    }
    limiter?.reset(ip, rateLimitScope);
    return { ok: true, method: "token" };
  }

  if (auth.mode === "password") {
    const password = connectAuth?.password;
    if (!auth.password) {
      return { ok: false, reason: "password_missing_config" };
    }
    if (!password) {
      limiter?.recordFailure(ip, rateLimitScope);
      return { ok: false, reason: "password_missing" };
    }
    if (!safeEqualSecret(password, auth.password)) {
      limiter?.recordFailure(ip, rateLimitScope);
      return { ok: false, reason: "password_mismatch" };
    }
    limiter?.reset(ip, rateLimitScope);
    return { ok: true, method: "password" };
  }

  limiter?.recordFailure(ip, rateLimitScope);
  return { ok: false, reason: "unauthorized" };
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////

export async function authorizeHttpGatewayConnect(
  params: Omit<AuthorizeGatewayConnectParams, "authSurface">,
): Promise<GatewayAuthResult> {
  return authorizeGatewayConnect({
    ...params,
    authSurface: "http",
  });
}

export async function authorizeWsControlUiGatewayConnect(
  params: Omit<AuthorizeGatewayConnectParams, "authSurface">,
): Promise<GatewayAuthResult> {
  return authorizeGatewayConnect({
    ...params,
    authSurface: "ws-control-ui",
  });
}
