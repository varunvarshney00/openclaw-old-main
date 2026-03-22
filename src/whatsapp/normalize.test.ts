// Ye jo file h, ye hmare WhatsApp Normalization module ka "Quality Assurance (QA) Lab" hai. Jo logic humne pichle kuch ghanton mein line-by-line samjha tha, ye test file us logic ko 100 alag-alag ajeeb inputs dekar verify kar rahi hai ki wo tootega toh nahi.
// Isko Unit Testing (via Vitest) kehte hain.

// Vitest hmara testing framework hai (bilkul Jest ki tarah, bas extremely fast). Ye teeno hmare lab ke (tools) hain:

// describe (The Container): Ye ek folder ya category hai. Ye batata hai ki "Hum kis machine ki testing shuru kar rahe hain?" (Jaise: "WhatsApp Normalizer Module").

// it (The Hypothesis/Scenario): Ye ek specific test case hai. Ye define karta hai ki "Agar main is machine mein X daalunga, toh kya Y niklega?" (Jaise: "it should clean double prefixes").

// expect (The Judge): Ye hmara measuring tape hai. Ye hmare function ke actual output ko pakadta hai aur verify karta hai ki kya wo expected output se match kar raha hai. Agar match nahi hua, toh terminal error dekar (red) ho jayega!
import { describe, expect, it } from "vitest";
import { isWhatsAppGroupJid, isWhatsAppUserTarget, normalizeWhatsAppTarget } from "./normalize.js";


// Ye code hmare main master function normalizeWhatsAppTarget ka "(Lie Detector) Test" hai.
// Isme hum function se (expectations) kar rahe hai ki wo alag-alag ajeeb inputs par kaisa behave karega.
describe("normalizeWhatsAppTarget", () => {
  it("preserves group JIDs", () => {

    // Tune ek perfect Group ID daali. Function ne dekha, "Ye toh pehle se sahi hai," aur exactly wahi wapas de di.
    expect(normalizeWhatsAppTarget("120363401234567890@g.us")).toBe("120363401234567890@g.us");

    // tune ek aisi ID daali jisme beech mein dash (-) hai (jo WhatsApp creator-timestamp format mein use karta hai). Tera function fail nahi hua, usne isko bhi safely pass hone diya.
    expect(normalizeWhatsAppTarget("123456789-987654321@g.us")).toBe("123456789-987654321@g.us");

    // 
    expect(normalizeWhatsAppTarget("whatsapp:120363401234567890@g.us")).toBe(
      "120363401234567890@g.us",
    );
  });

  it("normalizes direct JIDs to E.164", () => {
    expect(normalizeWhatsAppTarget("1555123@s.whatsapp.net")).toBe("+1555123");
  });

  it("normalizes user JIDs with device suffix to E.164", () => {
    // This is the bug fix: JIDs like "41796666864:0@s.whatsapp.net" should
    // normalize to "+41796666864", not "+417966668640" (extra digit from ":0")
    expect(normalizeWhatsAppTarget("41796666864:0@s.whatsapp.net")).toBe("+41796666864");
    expect(normalizeWhatsAppTarget("1234567890:123@s.whatsapp.net")).toBe("+1234567890");
    // Without device suffix still works
    expect(normalizeWhatsAppTarget("41796666864@s.whatsapp.net")).toBe("+41796666864");
  });

  it("normalizes LID JIDs to E.164", () => {
    expect(normalizeWhatsAppTarget("123456789@lid")).toBe("+123456789");
    expect(normalizeWhatsAppTarget("123456789@LID")).toBe("+123456789");
  });

  it("rejects invalid targets", () => {
    expect(normalizeWhatsAppTarget("wat")).toBeNull();
    expect(normalizeWhatsAppTarget("whatsapp:")).toBeNull();
    expect(normalizeWhatsAppTarget("@g.us")).toBeNull();
    expect(normalizeWhatsAppTarget("whatsapp:group:@g.us")).toBeNull();
    expect(normalizeWhatsAppTarget("whatsapp:group:120363401234567890@g.us")).toBeNull();
    expect(normalizeWhatsAppTarget("group:123456789-987654321@g.us")).toBeNull();
    expect(normalizeWhatsAppTarget(" WhatsApp:Group:123456789-987654321@G.US ")).toBeNull();
    expect(normalizeWhatsAppTarget("abc@s.whatsapp.net")).toBeNull();
  });

  it("handles repeated prefixes", () => {

    // Yaad hai wo for(;;) wala infinite loop jo humne dekha tha? Ye test usko verify kar raha hai ki chahe "whatsapp:" do baar hi kyun na likha ho, loop usko dho-poch kar ekdum saaf number (+1555) bana dega.
    expect(normalizeWhatsAppTarget("whatsapp:whatsapp:+1555")).toBe("+1555");
    expect(normalizeWhatsAppTarget("group:group:120@g.us")).toBeNull();
  });
});

describe("isWhatsAppUserTarget", () => {
  it("detects user JIDs with various formats", () => {
    expect(isWhatsAppUserTarget("41796666864:0@s.whatsapp.net")).toBe(true);
    expect(isWhatsAppUserTarget("1234567890@s.whatsapp.net")).toBe(true);
    expect(isWhatsAppUserTarget("123456789@lid")).toBe(true);
    expect(isWhatsAppUserTarget("123456789@LID")).toBe(true);
    expect(isWhatsAppUserTarget("123@lid:0")).toBe(false);
    expect(isWhatsAppUserTarget("abc@s.whatsapp.net")).toBe(false);
    expect(isWhatsAppUserTarget("123456789-987654321@g.us")).toBe(false);
    expect(isWhatsAppUserTarget("+1555123")).toBe(false);
  });
});

describe("isWhatsAppGroupJid", () => {
  it("detects group JIDs with or without prefixes", () => {
    expect(isWhatsAppGroupJid("120363401234567890@g.us")).toBe(true);
    expect(isWhatsAppGroupJid("123456789-987654321@g.us")).toBe(true);
    expect(isWhatsAppGroupJid("whatsapp:120363401234567890@g.us")).toBe(true);
    expect(isWhatsAppGroupJid("whatsapp:group:120363401234567890@g.us")).toBe(false);
    expect(isWhatsAppGroupJid("x@g.us")).toBe(false);
    expect(isWhatsAppGroupJid("@g.us")).toBe(false);
    expect(isWhatsAppGroupJid("120@g.usx")).toBe(false);
    expect(isWhatsAppGroupJid("+1555123")).toBe(false);
  });
});
