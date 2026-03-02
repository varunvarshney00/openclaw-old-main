// Frontend pe jab tu new WebSocket('ws://localhost') likhta hai, toh backend mein sabse pehle ye file hit hoti hai. Ye naye connection ko accept karti hai, client ki details (IP, Browser) note karti hai, usko ek "Challenge" bhejti hai (security ke liye), ek timer set karti hai (ki agar 5 second mein password nahi diya toh bhaga dunga), aur jab client chala jata hai toh uski memory aur presence (online/offline status) saaf karti hai.

import { randomUUID } from "node:crypto";
import type { WebSocket, WebSocketServer } from "ws";
import { resolveCanvasHostUrl } from "../../infra/canvas-host-url.js";
import { removeRemoteNodeInfo } from "../../infra/skills-remote.js";
import { upsertPresence } from "../../infra/system-presence.js";
import type { createSubsystemLogger } from "../../logging/subsystem.js";
import { truncateUtf16Safe } from "../../utils.js";
import { isWebchatClient } from "../../utils/message-channel.js";
import type { AuthRateLimiter } from "../auth-rate-limit.js";
import type { ResolvedGatewayAuth } from "../auth.js";
import { isLoopbackAddress } from "../net.js";
import { getHandshakeTimeoutMs } from "../server-constants.js";
import type { GatewayRequestContext, GatewayRequestHandlers } from "../server-methods/types.js";
import { formatError } from "../server-utils.js";
import { logWs } from "../ws-log.js";
import { getHealthVersion, incrementPresenceVersion } from "./health-state.js";
import { broadcastPresenceSnapshot } from "./presence-events.js";
import { attachGatewayWsMessageHandler } from "./ws-connection/message-handler.js";
import type { GatewayWsClient } from "./ws-types.js";

type SubsystemLogger = ReturnType<typeof createSubsystemLogger>;

const LOG_HEADER_MAX_LEN = 300;
const LOG_HEADER_FORMAT_REGEX = /\p{Cf}/gu;

function replaceControlChars(value: string): string {
  let cleaned = "";
  for (const char of value) {
    const codePoint = char.codePointAt(0);
    if (
      codePoint !== undefined &&
      (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f))
    ) {
      cleaned += " ";
      continue;
    }
    cleaned += char;
  }
  return cleaned;
}

const sanitizeLogValue = (value: string | undefined): string | undefined => {
  if (!value) {
    return undefined;
  }
  const cleaned = replaceControlChars(value)
    .replace(LOG_HEADER_FORMAT_REGEX, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!cleaned) {
    return undefined;
  }
  if (cleaned.length <= LOG_HEADER_MAX_LEN) {
    return cleaned;
  }
  return truncateUtf16Safe(cleaned, LOG_HEADER_MAX_LEN);
};

export function attachGatewayWsConnectionHandler(params: {
  wss: WebSocketServer;
  clients: Set<GatewayWsClient>;
  port: number;
  gatewayHost?: string;
  canvasHostEnabled: boolean;
  canvasHostServerPort?: number;
  resolvedAuth: ResolvedGatewayAuth;
  /** Optional rate limiter for auth brute-force protection. */
  rateLimiter?: AuthRateLimiter;
  gatewayMethods: string[];
  events: string[];
  logGateway: SubsystemLogger;
  logHealth: SubsystemLogger;
  logWsControl: SubsystemLogger;
  extraHandlers: GatewayRequestHandlers;
  broadcast: (
    event: string,
    payload: unknown,
    opts?: {
      dropIfSlow?: boolean;
      stateVersion?: { presence?: number; health?: number };
    },
  ) => void;
  buildRequestContext: () => GatewayRequestContext;
}) {
  const {
    wss,
    clients,
    port,
    gatewayHost,
    canvasHostEnabled,
    canvasHostServerPort,
    resolvedAuth,
    rateLimiter,
    gatewayMethods,
    events,
    logGateway,
    logHealth,
    logWsControl,
    extraHandlers,
    broadcast,
    buildRequestContext,
  } = params;

  // KYA HAI: Backend ka WebSocket Server (wss) hamesha kaan laga ke sun raha hai. Jaise hi koi naya user connect karta hai, ye "connection" event fire hota hai.
  // Parameters:
  // socket: Ye wo pipe hai jiske through ab tu user ko message bhejega (socket.send()).
  // upgradeReq: WebSockets direct start nahi hote. Pehle ek normal HTTP request aati hai, phir wo "Upgrade" hoke WebSocket banti hai. Ye variable us initial HTTP request ka saara kaccha- चिट्ठा (headers, cookies) hold karta hai.
  wss.on("connection", (socket, upgradeReq) => {

    // Abhi user sirf connect hua hai, usne apna password/auth nahi diya hai, isliye ye null hai.
    let client: GatewayWsClient | null = null;

    // Track karne ke liye ki connection zinda hai ya nahi.
    let closed = false;

    // Timer lagane ke liye (ki kitni der se connect hai).
    const openedAt = Date.now();

    // KYA HAI: Jab bhi koi naya tab/browser connect hota hai, usko ek unique ID (connId) milti hai.
    const connId = randomUUID();

    const remoteAddr = (socket as WebSocket & { _socket?: { remoteAddress?: string } })._socket
      ?.remoteAddress;
    const headerValue = (value: string | string[] | undefined) =>
      Array.isArray(value) ? value[0] : value;

    // //////////////////////////////////////////////////////////////////////////
    // KYA HAI: HTTP upgrade request (jo WS banne se pehle aati hai) se client ka data extract karna.
    // KYU HAI (Full Stack Insight): Jab teri app kisi cloud (jaise Vercel/AWS) pe host hogi, toh direct IP load balancer ka aayega, asli user ka nahi. Asli user ka IP x-forwarded-for ya x-real-ip headers mein chhipa hota hai. Backend engineer ko ye pata hona chahiye!
    // Ye poora concept "Networking Headers" aur "Reverse Proxies" ka hai.

    // KYA HAI: Ye batata hai ki user ne address bar mein exactly kya type kiya tha (e.g., api.xorthax.com).
    // KYU CHAHIYE: Ek hi server pe multiple websites chal sakti hain. Backend isko padh ke decide karta hai ki "Achha, isne Xorthax manga hai, toh Xorthax ka data do."
    const requestHost = headerValue(upgradeReq.headers.host);

    // KYA HAI: Ye batata hai ki request kis website se aayi hai.
    // KYU CHAHIYE (Security): Maan le teri backend API hai api.xorthax.com. Tu chahta hai ki sirf tera React frontend (app.xorthax.com) hi isko call kar sake. Agar koi hacker apni website evil.com se tera backend bulayega, toh origin mein evil.com likha aayega. Tera backend use yahin block kar dega (Isko CORS bolte hain).
    const requestOrigin = headerValue(upgradeReq.headers.origin);

    // KYA HAI: Ye user ke browser aur device ki poori kundali hai (e.g., Mozilla/5.0 (iPhone; CPU iPhone OS 14_0... Safari/604.1)).
    // KYU CHAHIYE: Backend ko pata lagta hai ki user Mobile pe hai ya Desktop pe, Chrome pe hai ya Safari pe. Iske hisaab se backend sometimes alag data bhejta hai ya analytics track karta hai. (Jaise OpenClaw check karta hai ki kya connection kisi iOS app se aa raha hai).
    const requestUserAgent = headerValue(upgradeReq.headers["user-agent"]);

    // KYA HAI: Ye dono wahi "Cheat Codes" hain jo Waiter (Load Balancer) Chef ko deta hai.
    // KAISE KAAM KARTA HAI: Jab traffic AWS ya Cloudflare se hokar gujarta hai, toh wo beech wale servers apna IP toh backend ko de dete hain, par asli customer ka IP chup-chaap ek naye header x-forwarded-for ya x-real-ip mein likh kar bhej dete hain.
    // KYU CHAHIYE: Agar tera Xorthax server ek IP address se ek second mein 1000 requests (DDoS attack) receive karta hai, toh tera "Rate Limiter" us IP ko block karega. Agar tu x-forwarded-for nahi padhega, toh tu galti se Cloudflare ka IP block kar dega aur teri poori website saare users ke liye band ho jayegi! Is header ko padhne se tu us specific hacker ka asli IP nikal kar sirf usko block kar sakta hai.
    const forwardedFor = headerValue(upgradeReq.headers["x-forwarded-for"]);
    const realIp = headerValue(upgradeReq.headers["x-real-ip"]);
    /////////////////////////////////////////////////////////////////////////////////////

    // OpenClaw ke andar ek "Canvas" feature hai (ek visual workspace jahan AI UI draw karta hai). Ye code block backend mein us Canvas ka sahi URL calculate kar raha hai. Server ko khud nahi pata hota ki bahar ki duniya mein uska naam kya hai (wo localhost hai, ya xorthax.com hai). Ye code headers aur config ko jod kar wo exact URL banata hai taaki frontend ko pata chale ki Canvas kahan se load karna hai.
    const canvasHostPortForWs = canvasHostServerPort ?? (canvasHostEnabled ? port : undefined);

    console.log("canvasHostPortForWs-->", canvasHostPortForWs)

    const canvasHostOverride =
      gatewayHost && gatewayHost !== "0.0.0.0" && gatewayHost !== "::" ? gatewayHost : undefined;

      // Server (Backend) ek andhere kamre mein baitha hota hai. Usko khud nahi pata hota ki bahar internet pe uska naam localhost hai, ya api.xorthax.com hai, ya wo http pe chal रहा hai ya https pe. Lekin tere Frontend (React UI) ko ek exact URL chahiye hota hai iframe ya images load karne ke liye. Ye function un saare tukdon ko jod kar ek perfect, absolute URL banata hai jise frontend samajh sake.
      const canvasHostUrl = resolveCanvasHostUrl( {
        // Ye wo port hai jo humne pichli line mein calculate kiya tha (jaise 18789 ya 3000).
        // URL mein port lagana zaroori hota hai agar wo standard 80 (HTTP) ya 443 (HTTPS) nahi hai.
      canvasPort: canvasHostPortForWs,
      hostOverride: canvasHostServerPort ? canvasHostOverride : undefined,

        // WebSocket request ke headers mein se host nikalna. (e.g., jab tu browser mein localhost:18789 daalta hai, toh browser chup-chaap ek parchi bhejta hai: Host: localhost:18789).
        // Ye server ko batata hai ki user ne address bar mein kya type kiya tha. Ye URL banane ka sabse reliable source hai!
      requestHost: upgradeReq.headers.host,

        // KYA HAI: The Security Badge. Ye Nginx, AWS, ya Cloudflare jaise Load Balancers ka header hai.
        // KYU CHAHIYE (Full Stack Pro-Tip): Tera Node.js server production mein hamesha http (insecure) par chalta hai, aur uske aage baitha Load Balancer https (secure) handle karta hai. Agar Node.js khud url banayega toh wo http://... bana dega, aur tera frontend gusse mein "Mixed Content Error" phek dega. Ye x-forwarded-proto server ko batata hai ki "Bhai, user securely aaya hai, toh tu URL mein https:// lagana!"
      forwardedProto: upgradeReq.headers["x-forwarded-proto"],

      // KYA HAI: The Fallback (Aakhri Rasta). Underlying network socket se server ka internal IP address nikalna (jaise 192.168.1.5 ya 127.0.0.1).
      // KYU CHAHIYE: Agar upar wale saare headers missing hain (maan le kisi ne curl se ajeeb si request maari), toh system kam se kam apne local network address ka use karke ek kaam-chalau URL bana sake taaki app crash na ho.
      localAddress: upgradeReq.socket?.localAddress,
    });
    /////////////////////////////////////////////////////////////////////////////////////

    // Frontend pe jab tu React state banata hai (useState), toh wo component ka data track karta hai. Backend mein jab koi naya WebSocket connection banta hai, toh server ko us single connection ka poora "State" (halat) track karna padta hai. Ye saare let variables us ek user connection ka Medical Record hain. Agar connection beech mein toot jaye, toh backend engineer inhi variables ko dekh kar pata lagata hai ki galti kiski thi—client ka internet gaya, ya server fat gaya.
    
    // KYA HAI: Ye ek custom logging function hai. Jaise hi connection start hota hai, ye system ki log file mein entry maar deta hai ki "Ek naya connection AANDAR (in) aaya hai, OPEN hua hai, uski ID ye hai aur uska IP Address ye hai."
    // KYU HAI (Backend Reality): Frontend pe console.log browser mein dikhta hai. Backend mein, log files hi teri aakhein hoti hain. Agar production mein server hang ho raha hai, toh tu logs check karke dekh sakta hai ki kis IP address se kitne connections open ho rahe hain.
    logWs("in", "open", { connId, remoteAddr });

    // KYU HAI: WebSocket direct open hote hi secure nahi hota. Server pehle frontend ko ek challenge (password/token) bhejta hai. Jab tak frontend wo token wapas verify nahi karta, state "pending" rahegi. Agar token sahi nikla toh "connected", warna "failed"
    // Full Stack Insight: Ye bilkul waisa hi hai jaise frontend mein tu API call karte waqt isLoading, isSuccess, aur isError track karta hai.
    let handshakeState: "pending" | "connected" | "failed" = "pending";
    // Agar connection close/disconnect ho jata hai, toh ye do variables us disconnection ka kaaran (Cause) aur uski details (Meta) store karne ke liye banaye gaye hain. Record<string, unknown> TypeScript ka tarika hai ek khali object {} define karne ka jisme kuch bhi key-value pair daala ja sake.
    let closeCause: string | undefined;
    let closeMeta: Record<string, unknown> = {};

    // WebSockets mein data lamba text ban ke nahi jata, wo chhote-chhote packets mein jata hai jinko "Frames" bolte hain (jaise train ke dabbe). Har frame ka ek Type, ek Method (kaam kya hai), aur ek ID hoti hai.
    let lastFrameType: string | undefined;
    let lastFrameMethod: string | undefined;
    let lastFrameId: string | undefined;

    const setCloseCause = (cause: string, meta?: Record<string, unknown>) => {
      if (!closeCause) {
        closeCause = cause;
      }
      if (meta && Object.keys(meta).length > 0) {
        closeMeta = { ...closeMeta, ...meta };
      }
    };

    const setLastFrameMeta = (meta: { type?: string; method?: string; id?: string }) => {
      if (meta.type || meta.method || meta.id) {
        lastFrameType = meta.type ?? lastFrameType;
        lastFrameMethod = meta.method ?? lastFrameMethod;
        lastFrameId = meta.id ?? lastFrameId;
      }
    };

    // Frontend aur Backend ke beech mein jab WebSocket pe baat hoti hai, toh wo JavaScript ke Objects {} nahi bhej sakte. Unhe data ko ek lamba text (String) banana padta hai. Ye function tere server ka "Postman" hai. Ye kisi bhi object ko leta hai, usko text mein convert karta hai, aur frontend ko bhej deta hai. Aur sabse badi baat, agar frontend achanak se disconnect ho jaye bhejte waqt, toh ye function chup-chaap us error ko daba deta hai taaki server crash na ho.
    const send = (obj: unknown) => {
      try {
        socket.send(JSON.stringify(obj));
      } catch {
        /* ignore */
      }
    };

    const connectNonce = randomUUID();
    send({
      type: "event",
      event: "connect.challenge",
      payload: { nonce: connectNonce, ts: Date.now() },
    });

    const close = (code = 1000, reason?: string) => {
      if (closed) {
        return;
      }
      closed = true;
      clearTimeout(handshakeTimer);
      if (client) {
        clients.delete(client);
      }
      try {
        socket.close(code, reason);
      } catch {
        /* ignore */
      }
    };

    socket.once("error", (err) => {
      logWsControl.warn(`error conn=${connId} remote=${remoteAddr ?? "?"}: ${formatError(err)}`);
      close();
    });

    const isNoisySwiftPmHelperClose = (userAgent: string | undefined, remote: string | undefined) =>
      Boolean(
        userAgent?.toLowerCase().includes("swiftpm-testing-helper") && isLoopbackAddress(remote),
      );

    socket.once("close", (code, reason) => {
      const durationMs = Date.now() - openedAt;
      const logForwardedFor = sanitizeLogValue(forwardedFor);
      const logOrigin = sanitizeLogValue(requestOrigin);
      const logHost = sanitizeLogValue(requestHost);
      const logUserAgent = sanitizeLogValue(requestUserAgent);
      const logReason = sanitizeLogValue(reason?.toString());
      const closeContext = {
        cause: closeCause,
        handshake: handshakeState,
        durationMs,
        lastFrameType,
        lastFrameMethod,
        lastFrameId,
        host: logHost,
        origin: logOrigin,
        userAgent: logUserAgent,
        forwardedFor: logForwardedFor,
        ...closeMeta,
      };
      if (!client) {
        const logFn = isNoisySwiftPmHelperClose(requestUserAgent, remoteAddr)
          ? logWsControl.debug
          : logWsControl.warn;
        logFn(
          `closed before connect conn=${connId} remote=${remoteAddr ?? "?"} fwd=${logForwardedFor || "n/a"} origin=${logOrigin || "n/a"} host=${logHost || "n/a"} ua=${logUserAgent || "n/a"} code=${code ?? "n/a"} reason=${logReason || "n/a"}`,
          closeContext,
        );
      }
      if (client && isWebchatClient(client.connect.client)) {
        logWsControl.info(
          `webchat disconnected code=${code} reason=${logReason || "n/a"} conn=${connId}`,
        );
      }
      if (client?.presenceKey) {
        upsertPresence(client.presenceKey, { reason: "disconnect" });
        broadcastPresenceSnapshot({ broadcast, incrementPresenceVersion, getHealthVersion });
      }
      if (client?.connect?.role === "node") {
        const context = buildRequestContext();
        const nodeId = context.nodeRegistry.unregister(connId);
        if (nodeId) {
          removeRemoteNodeInfo(nodeId);
          context.nodeUnsubscribeAll(nodeId);
        }
      }
      logWs("out", "close", {
        connId,
        code,
        reason: logReason,
        durationMs,
        cause: closeCause,
        handshake: handshakeState,
        lastFrameType,
        lastFrameMethod,
        lastFrameId,
      });
      close();
    });

    const handshakeTimeoutMs = getHandshakeTimeoutMs();
    const handshakeTimer = setTimeout(() => {
      if (!client) {
        handshakeState = "failed";
        setCloseCause("handshake-timeout", {
          handshakeMs: Date.now() - openedAt,
        });
        logWsControl.warn(`handshake timeout conn=${connId} remote=${remoteAddr ?? "?"}`);
        close();
      }
    }, handshakeTimeoutMs);

    attachGatewayWsMessageHandler({
      socket,
      upgradeReq,
      connId,
      remoteAddr,
      forwardedFor,
      realIp,
      requestHost,
      requestOrigin,
      requestUserAgent,
      canvasHostUrl,
      connectNonce,
      resolvedAuth,
      rateLimiter,
      gatewayMethods,
      events,
      extraHandlers,
      buildRequestContext,
      send,
      close,
      isClosed: () => closed,
      clearHandshakeTimer: () => clearTimeout(handshakeTimer),
      getClient: () => client,
      setClient: (next) => {
        client = next;
        clients.add(next);
      },
      setHandshakeState: (next) => {
        handshakeState = next;
      },
      setCloseCause,
      setLastFrameMeta,
      logGateway,
      logHealth,
      logWsControl,
    });
  });
}
