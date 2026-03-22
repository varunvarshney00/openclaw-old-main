// Socho tumhe apne laptop se ek remote AI server (Gateway) se connect karna hai. 
// Uske liye tumhe ek lamba choda address, secret password, aur configuration deni padegi. 
// Yeh file tumhe ek neat aur simple tarika deti hai terminal mein command type karke us remote system se connect hone ka (jaise openclaw acp --token mytoken). 
// Yeh user ki aadi tension yahin khatam kar deta hai ki input kaise lena hai.

// Data Flow Journey
// User action hoti hai → Developer terminal mein command type karta hai (e.g., acp --token 123 --verbose).
// Library parse karti hai → commander library is text ko padh kar samajhti hai ki user kya chahta hai.
// Validation hoti hai → Code check karta hai ki token file se aaya hai ya direct likha gaya hai (resolveSecretOption function ke through).
// Security Check hota hai → Agar password khule aam screen par type kiya gaya hai, toh system ek warning fekta hai (warnSecretCliFlag).
// Action Execute hota hai → Sab kuch sahi hone par, data aage badha diya jata hai aur asli background server ya client start ho jata hai.

// Real-life analogy: Yeh file ek Restaurant ke Waiter ki tarah kaam karti hai. Tum (User) apna order (Command) dete ho. Waiter us order ko sunta hai, apne notepad par note karta hai (Parsing), dekhta hai ki koi item menu mein hai ya nahi (Validation), aur fir exactly order le jaakar andar Kitchen mein Chef (Gateway/Client code) ko de deta hai banane ke liye. Yeh file khud khana (logic) nahi banati, sirf order pass karti hai.

// ACP = Agent Control Protocol
// Matlab: Ek protocol (communication rule set) jiske through clients, gateways, aur agents aapas me baat karte hain.


import type { Command } from "commander";
import { runAcpClientInteractive } from "../acp/client.js";
import { readSecretFromFile } from "../acp/secret-file.js";
import { serveAcpGateway } from "../acp/server.js";
import { defaultRuntime } from "../runtime.js";
import { formatDocsLink } from "../terminal/links.js";
import { theme } from "../terminal/theme.js";
import { inheritOptionFromParent } from "./command-options.js";

function resolveSecretOption(params: {
  direct?: string;
  file?: string;
  directFlag: string;
  fileFlag: string;
  label: string;
}) {
  const direct = params.direct?.trim();
  const file = params.file?.trim();
  if (direct && file) {
    throw new Error(`Use either ${params.directFlag} or ${params.fileFlag} for ${params.label}.`);
  }
  if (file) {
    return readSecretFromFile(file, params.label);
  }
  return direct || undefined;
}

function warnSecretCliFlag(flag: "--token" | "--password") {
  defaultRuntime.error(
    `Warning: ${flag} can be exposed via process listings. Prefer ${flag}-file or environment variables.`,
  );
}

export function registerAcpCli(program: Command) {
  const acp = program.command("acp").description("Run an ACP bridge backed by the Gateway");

  acp
    .option("--url <url>", "Gateway WebSocket URL (defaults to gateway.remote.url when configured)")
    .option("--token <token>", "Gateway token (if required)")
    .option("--token-file <path>", "Read gateway token from file")
    .option("--password <password>", "Gateway password (if required)")
    .option("--password-file <path>", "Read gateway password from file")
    .option("--session <key>", "Default session key (e.g. agent:main:main)")
    .option("--session-label <label>", "Default session label to resolve")
    .option("--require-existing", "Fail if the session key/label does not exist", false)
    .option("--reset-session", "Reset the session key before first use", false)
    .option("--no-prefix-cwd", "Do not prefix prompts with the working directory", false)
    .option("-v, --verbose", "Verbose logging to stderr", false)
    .addHelpText(
      "after",
      () => `\n${theme.muted("Docs:")} ${formatDocsLink("/cli/acp", "docs.openclaw.ai/cli/acp")}\n`,
    )
    .action(async (opts) => {
      try {
        const gatewayToken = resolveSecretOption({
          direct: opts.token as string | undefined,
          file: opts.tokenFile as string | undefined,
          directFlag: "--token",
          fileFlag: "--token-file",
          label: "Gateway token",
        });
        const gatewayPassword = resolveSecretOption({
          direct: opts.password as string | undefined,
          file: opts.passwordFile as string | undefined,
          directFlag: "--password",
          fileFlag: "--password-file",
          label: "Gateway password",
        });
        if (opts.token) {
          warnSecretCliFlag("--token");
        }
        if (opts.password) {
          warnSecretCliFlag("--password");
        }
        await serveAcpGateway({
          gatewayUrl: opts.url as string | undefined,
          gatewayToken,
          gatewayPassword,
          defaultSessionKey: opts.session as string | undefined,
          defaultSessionLabel: opts.sessionLabel as string | undefined,
          requireExistingSession: Boolean(opts.requireExisting),
          resetSession: Boolean(opts.resetSession),
          prefixCwd: !opts.noPrefixCwd,
          verbose: Boolean(opts.verbose),
        });
      } catch (err) {
        defaultRuntime.error(String(err));
        defaultRuntime.exit(1);
      }
    });

  acp
    .command("client")
    .description("Run an interactive ACP client against the local ACP bridge")
    .option("--cwd <dir>", "Working directory for the ACP session")
    .option("--server <command>", "ACP server command (default: openclaw)")
    .option("--server-args <args...>", "Extra arguments for the ACP server")
    .option("--server-verbose", "Enable verbose logging on the ACP server", false)
    .option("-v, --verbose", "Verbose client logging", false)
    .action(async (opts, command) => {
      const inheritedVerbose = inheritOptionFromParent<boolean>(command, "verbose");
      try {
        await runAcpClientInteractive({
          cwd: opts.cwd as string | undefined,
          serverCommand: opts.server as string | undefined,
          serverArgs: opts.serverArgs as string[] | undefined,
          serverVerbose: Boolean(opts.serverVerbose),
          verbose: Boolean(opts.verbose || inheritedVerbose),
        });
      } catch (err) {
        defaultRuntime.error(String(err));
        defaultRuntime.exit(1);
      }
    });
}
