// Ye jo file hai, ye hmare systm ka "data sanitizer" hai. Specifically whatsapp numbers and ids k liye.
// Jab tu WhatsApp API (jaise Meta ya Twilio) ke saath integration karta hai, toh har API user ke phone number ko alag format mein bhejti hai.
// Koi bhejega: whatsapp:+919876543210
// Koi bhejega: 919876543210@s.whatsapp.net (WhatsApp ka internal format)
// Koi bhejega: 919876543210:2@s.whatsapp.net (Linked device ID ke saath)
// Koi group ka ID bhejega: 123456789-987654@g.us
// Agar tera backend in sab ajeeb formats ko database mein direct save kar dega, toh baad mein search ya match karna impossible ho jayega. Ye file in saare ajeeb formats ko padhti hai, unme se kachra (prefixes/suffixes) hatati hai, aur ek Clean, Standardized E.164 Format (jaise +919876543210) mein badal kar wapas deti hai.

// Flow ko aise samajh:
// Tera user apne phone pe WhatsApp kholta hai aur tere OpenClaw bot ko message likhta hai: "Hi AI".
// Ye message direct tere Node.js server pe nahi aata. Ye sabse pehle Meta (WhatsApp ke asli malik) ke server pe jata hai.
// Meta ka server check karta hai: "Achha, ye message OpenClaw ke business number pe aaya hai."
// Ab Meta tere server (Gateway) ko ek Webhook (HTTP POST Request) bhejta hai.

// "Bhejti hai" ka matlab: Meta tera ek API endpoint (jaise https://api.OpenClaw.com/whatsapp/webhook) hit karta hai aur usme ek lamba-chauda JSON data phek deta hai. Is JSON mein likha hota hai: "Is number se, is time par, ye text message aaya hai."

// Toh jab main kehta hoon "API alag format mein bhejti hai", uska matlab hai Meta ya Twilio tere webhook pe jo JSON bhejte hain, usme user ka phone number unke apne ajeeb tarike se likha hota hai.

// 2. "WhatsApp ka internal format matlab?" (The JID / Jabber ID)
// Hum log phone numbers ko digits mein dekhte hain (9876543210), par WhatsApp ki internal programming isko aise nahi dekhti.
// WhatsApp actually ek purane chat protocol par bana tha jiska naam tha XMPP (Jabber). Is protocol mein har user ki ek ID hoti hai jo bilkul Email ID jaisi dikhti hai. Isko JID (Jabber ID) kehte hain.
// Single User JID: 919876543210@s.whatsapp.net (WhatsApp ko pata chalta hai ki ye ek aam insaan hai).
// Group JID: 123456789-987654@g.us (@g.us ka matlab 'Group User'. Isse system group aur single chat mein farq samajhta hai).
// Linked Device JID: Aaj kal hum WhatsApp Web bhi chalate hain (ek account, 4 devices). Toh WhatsApp internal data mein isko aise likhta hai: 919876543210:1@s.whatsapp.net (Jahan :1 tera laptop hai, aur :2 tera iPad).
// Toh jab Meta tere webhook pe data bhejta hai, wo seedha number nahi bhejta, wo ye poori JID bhej deta hai. Teri pichli file ka kaam yahi tha ki is JID mein se @s.whatsapp.net ya :1 ko kaat kar phek de aur sirf number nikaal le.

// 3. "E.164 Format kya hota hai?" (The Global Standard)
// Soch ki tere database mein ek user ka number save hai: 9876543210.
// Ab tera backend is number pe WhatsApp message bhejne ki koshish kar raha hai. Par ye number India ka hai (+91), USA ka hai (+1), ya UK ka hai (+44)? Database mein toh Country Code hai hi nahi! Backend confuse hoke fail ho jayega.
// Is problem ko solve karne ke liye telecommunications ki duniya mein ek International Standard banaya gaya jisko E.164 kehte hain.
// E.164 ka strict rule kya hai:
// Hamesha + sign se shuru hoga.
// Uske turant baad Country Code hoga (jaise 91).
// Uske baad Phone Number hoga.
// Koi space nahi, koi dash (-) nahi, koi bracket () nahi. Maximum 15 digits.
// Examples:
// ❌ Kachra format: 09876-543210 ya (91) 98765 43210
// ✅ E.164 Format: +919876543210

import { normalizeE164 } from "../utils.js";
// Duniya bhar se log alag-alag, ajeeb tareeqe se apna phone number type karte hain. Ye function us "kachre" wale number ko leta hai, uski saaf-safai karta hai, aur usko ek perfect, universal standard (E.164 format) mein badal kar tere database ko deta hai.

const WHATSAPP_USER_JID_RE = /^(\d+)(?::\d+)?@s\.whatsapp\.net$/i;
// KYA HAI: Ye Regular Expressions (Regex) hain. Ye string match karne ke sabse fast tareeqe hain.
// WhatsApp internally phone numbers nahi samajhta, wo "JIDs" (Jabber IDs) samajhta hai.

// 1. The Main Scanner (WHATSAPP_USER_JID_RE)
// Ye regex aam WhatsApp users ki ID ko pehchanta hai (Jaise: 919876543210:1@s.whatsapp.net).
// Code: /^(\d+)(?::\d+)?@s\.whatsapp\.net$/i

// Iske tukde karte hain:
// / ... /i : Ye regex ka box hai. Aakhiri mein jo i hai, uska matlab hai "Case Insensitive" (Matlab chahe @S.WhatsApp.net likha हो ya @s.whatsapp.net, dono chalega).

// ^ aur $ : Ye guards hain. ^ ka matlab "String yahin se shuru honi chahiye" aur $ ka matlab "Yahin pe khatam honi chahiye". Ye ensure karta hai ki string ke aage-peeche koi ajeeb kachra na ho.

// (\d+) (The Core Engine) : \d matlab koi bhi number (0-9). + matlab "ek ya usse zyada". Aur brackets () ka matlab hai Capture Group. Ye backend ko bolta hai: "Is hisse ko pakad ke rakh lo, yehi humara asli phone number hai!"

// (?::\d+)? (The Optional Device ID) : Ye sabse smart part hai. WhatsApp Web use karne pe ID ke aage :1 ya :2 lag jata hai.
// : matlab colon hona chahiye.
// \d+ matlab uske baad numbers hone chahiye.
// Baahar wale ? ka matlab hai "Optional" (Ye hissa ho bhi sakta hai, aur nahi bhi).
// (?: ... ) ka matlab hai "Is hisse ko match zaroor karna, par isko save (capture) mat karna kyunki hume sirf phone number se matlab hai, device ID se nahi."

// @s\.whatsapp\.net : Ye check karta hai ki string exactly is address pe end ho rahi hai (dot . ko bachane ke liye \ lagaya gaya hai).

const WHATSAPP_LID_RE = /^(\d+)@lid$/i;
// 2. The Privacy Scanner (WHATSAPP_LID_RE)
// WhatsApp aajkal phone numbers chhupane ke liye ek naya "LID" (Local ID) format use karta hai jisme number ki jagah random digits hote hain. (Jaise: 1234567890@lid).

// Code: /^(\d+)@lid$/i
// Iska flow ekdum simple hai:

// Shuru se leke end tak (^ se $) match karo.
// Numbers ka ek guccha pakdo (\d+) aur usko save kar lo.
// Ensure karo ki end mein @lid likha ho.
// Case insensitive rakho (i).


function stripWhatsAppTargetPrefixes(value: string): string {
  
  // Sabse pehle input ke aage-peeche ke extra spaces hataye. Ab humare paas candidate (mareez) hai.
  let candidate = value.trim();

  // Ye ek Infinite Loop hai. Ye tab tak chalega jab tak hum isko khud andar se return karke bahar nahi aate.
  for (;;) {
    const before = candidate;

    candidate = candidate.replace(/^whatsapp:/i, "").trim();
    // ^ (Start): Sirf string ke shuru mein check karo.
    // i (Case Insensitive): Chahe "WhatsApp:" ho ya "whatsapp:", sab pakad lo.
    // Usko khali string "" se replace kar do aur wapas spaces (trim) hata do.
    // Ab naya candidate ban gaya: "whatsapp:+9198765" (Ek prefix hat gaya).

    if (candidate === before) {
      return candidate;
    }
  }
}
// KYA HAI: Ye function string ke aage se "whatsapp:" hatata hai.
// Jab tu Twilio jaisi API use karta hai WhatsApp ke liye, toh wo phone number bhejte waqt uske aage apni taraf se "whatsapp:" laga dete hain. (Jaise: whatsapp:+919876543210).
// Tera backend chahta hai sirf +919876543210.
// Ek Junior Developer likhega:
// value.replace("whatsapp:", "")
// Par isme bug kya hai? Kabhi-kabhi APIs mein glitch hota hai, ya do systems aapas mein judte hain, toh input aisa aa jata hai:
// whatsapp: whatsapp:+919876543210 (Double prefix!)
// Junior developer ka code ek "whatsapp:" hatayega, par doosra chhoot jayega, aur database mein galat entry chali jayegi.


// Jab Meta tere server ko koi message bhejta hai, toh backend ko pata hona chahiye ki ye message kisi single user ne bheja hai (Direct Message) ya kisi group mein aaya hai. Kyunki group messages ka database schema aur AI ka reply karne ka context bilkul alag hota hai.
export function isWhatsAppGroupJid(value: string): boolean {

  // Sabse pehle, jo pichla function humne padha tha (stripWhatsAppTargetPrefixes), usko use karke "whatsapp:" wale kachre ko hataya. Ab humare paas clean string hai (candidate).
  const candidate = stripWhatsAppTargetPrefixes(value);
  
  // WhatsApp ka internal rule hai ki duniya ka har ek WhatsApp group @g.us (Group User) par end hota hai. (Jabki single user @s.whatsapp.net pe).
  // Pehle string ko lowercase kiya taaki @G.US jaisi ajeeb casing se bug na aaye, aur check kiya ki kya ye us suffix se end ho raha hai? Agar nahi, toh turant false phek do. Ye Group nahi hai.
  const lower = candidate.toLowerCase();
  if (!lower.endsWith("@g.us")) {
    return false;
  }


  const localPart = candidate.slice(0, candidate.length - "@g.us".length);
  // The Extraction: Ab hume suffix (@g.us) toh mil gaya. Ab uske aage ka hissa (jisme actual group ki ID chhupi hai) nikalna hai.
  // Example: Agar string hai 12345-6789@g.us, toh ye code aakhri ke 5 characters (@g.us) ko kaat dega aur localPart mein sirf 12345-6789 save karega.


  if (!localPart || localPart.includes("@")) {
    return false;
  }
  // : Kya suffix hatane ke baad aage kuch bacha bhi hai? (Aisa toh nahi kisi ne sirf @g.us bhej diya ho).
  // Kya bache hue hisse mein ek aur @ hai? (Agar string user@hacker@g.us thi, toh ye pakad lega).
  // Agar inme se kuch bhi gadbad hai, toh reject kar do.


  return /^[0-9]+(-[0-9]+)*$/.test(localPart);
  // Ab localPart mein humare paas Group ki ID hai (jaise 1234567890-1612345678). Ye line check karti hai ki kya ye sach mein numbers aur hyphens (-) ka sahi combination hai?
  // ^[0-9]+: Shuruat strictly numbers se honi chahiye.
  // (-[0-9]+)*$: Uske baad ek dash (hyphen) aur kuch numbers aa sakte hain, aur string wahin strictly end ($) honi chahiye.
  // WhatsApp groups ki internal ID aksar [CreatorPhoneNumber]-[CreationTimestamp] ke format mein hoti hai, isliye ye dash - allow kiya gaya hai.
}




/**
 * Check if value looks like a WhatsApp user target (e.g. "41796666864:0@s.whatsapp.net" or "123@lid").
 */
export function isWhatsAppUserTarget(value: string): boolean {
  const candidate = stripWhatsAppTargetPrefixes(value);
  return WHATSAPP_USER_JID_RE.test(candidate) || WHATSAPP_LID_RE.test(candidate);
}




/**
 * Extract the phone number from a WhatsApp user JID.
 * "41796666864:0@s.whatsapp.net" -> "41796666864"
 * "123456@lid" -> "123456"
 */
function extractUserJidPhone(jid: string): string | null {
  const userMatch = jid.match(WHATSAPP_USER_JID_RE);
  if (userMatch) {
    return userMatch[1];
  }
  const lidMatch = jid.match(WHATSAPP_LID_RE);
  if (lidMatch) {
    return lidMatch[1];
  }
  return null;
}

// Yahi wo main function hai jisko tera API router call karega jab bhi WhatsApp se koi message aayega.
export function normalizeWhatsAppTarget(value: string): string | null {
  const candidate = stripWhatsAppTargetPrefixes(value);
  if (!candidate) {
    return null;
  }

  // 
  if (isWhatsAppGroupJid(candidate)) {
    const localPart = candidate.slice(0, candidate.length - "@g.us".length);
    return `${localPart}@g.us`;
  }
  // Handle user JIDs (e.g. "41796666864:0@s.whatsapp.net")
  if (isWhatsAppUserTarget(candidate)) {
    const phone = extractUserJidPhone(candidate);
    if (!phone) {
      return null;
    }
    const normalized = normalizeE164(phone);
    return normalized.length > 1 ? normalized : null;
  }
  // If the caller passed a JID-ish string that we don't understand, fail fast.
  // Otherwise normalizeE164 would happily treat "group:120@g.us" as a phone number.
  if (candidate.includes("@")) {
    return null;
  }
  const normalized = normalizeE164(candidate);
  return normalized.length > 1 ? normalized : null;
}
