// Frontend mein tu likhta hai const ws = new WebSocket('ws://127.0.0.1:18789'). Par backend mein us connection ko "Receive" kaun karta hai? Ye file backend ka "Receptionist" hai. Jab bhi koi naya client (tera UI ya phone) connect hota hai, ye function usko server ke baaki hisson (Auth, Rate Limiter, Logs, Chat Handlers) se introduce karwata hai. Ye saari configuration ko ek jagah bundle karke actual connection manager ko pass kar deta hai.

import type { WebSocketServer } from "ws";
import type { createSubsystemLogger } from "../logging/subsystem.js";
import type { AuthRateLimiter } from "./auth-rate-limit.js";
import type { ResolvedGatewayAuth } from "./auth.js";
import type { GatewayRequestContext, GatewayRequestHandlers } from "./server-methods/types.js";

// Ye akela actual JavaScript import hai jo runtime pe execute hoga. Ye wo main worker function hai jo aage jaake connections handle karega.
import { attachGatewayWsConnectionHandler } from "./server/ws-connection.js";

import type { GatewayWsClient } from "./server/ws-types.js";

export function attachGatewayWsHandlers(params: {
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
  logGateway: ReturnType<typeof createSubsystemLogger>;
  logHealth: ReturnType<typeof createSubsystemLogger>;
  logWsControl: ReturnType<typeof createSubsystemLogger>;
  extraHandlers: GatewayRequestHandlers;
  broadcast: (
    event: string,
    payload: unknown,
    opts?: {
      dropIfSlow?: boolean;
      stateVersion?: { presence?: number; health?: number };
    },
  ) => void;
  context: GatewayRequestContext;

}) {
  attachGatewayWsConnectionHandler({
    wss: params.wss,
    clients: params.clients,
    port: params.port,
    gatewayHost: params.gatewayHost,
    canvasHostEnabled: params.canvasHostEnabled,
    canvasHostServerPort: params.canvasHostServerPort,
    resolvedAuth: params.resolvedAuth,
    rateLimiter: params.rateLimiter,
    gatewayMethods: params.gatewayMethods,
    events: params.events,
    logGateway: params.logGateway,
    logHealth: params.logHealth,
    logWsControl: params.logWsControl,
    extraHandlers: params.extraHandlers,
    broadcast: params.broadcast,
    buildRequestContext: () => params.context,
  });
}
