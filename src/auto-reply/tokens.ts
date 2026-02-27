import { escapeRegExp } from "../utils.js";

export const HEARTBEAT_TOKEN = "HEARTBEAT_OK";
export const SILENT_REPLY_TOKEN = "NO_REPLY";

// Jab AI background mein koi tool run karta hai ya internal process karta hai, toh wo apne message ke andar ek "Silent Token" (ek secret code/word) laga deta hai. Is function ka kaam hai check karna ki kya AI ke bheje gaye message mein wo secret token sabse shuru mein (prefix) ya sabse aakhri mein (suffix) laga hai. Agar laga hai, toh iska matlab ye message user ko UI pe nahi dikhana hai (Silent = True).

// text (AI ka lamba message) aur token (wo secret code jisko dhundhna hai).
export function isSilentReplyText(
  text: string | undefined,
  token: string = SILENT_REPLY_TOKEN,
): boolean {
  if (!text) {
    return false;
  }
  const escaped = escapeRegExp(token);
  const prefix = new RegExp(`^\\s*${escaped}(?=$|\\W)`);
  if (prefix.test(text)) {
    return true;
  }
  const suffix = new RegExp(`\\b${escaped}\\b\\W*$`);
  return suffix.test(text);
}

export function isSilentReplyPrefixText(
  text: string | undefined,
  token: string = SILENT_REPLY_TOKEN,
): boolean {
  if (!text) {
    return false;
  }
  const normalized = text.trimStart().toUpperCase();
  if (!normalized) {
    return false;
  }
  if (!normalized.includes("_")) {
    return false;
  }
  if (/[^A-Z_]/.test(normalized)) {
    return false;
  }
  return token.toUpperCase().startsWith(normalized);
}
