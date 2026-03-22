// hmara database messages ko alag tareeqe se save karta hai, par OpenAI ya Claude ko prompt ek specific text format mein chahiye hota hai. 
// Ye file us data ko ek proper prompt mein badalti hai taaki AI usko samajh sake.

// Ye file ensure karti hai ki:
// Multi-modal (Image+Text) messages crash na karein.
// AI khud ko reply na kare.
// History ekdum structured "Sender: Message" format mein LLM tak pahuche.




import { buildHistoryContextFromEntries, type HistoryEntry } from "../auto-reply/reply/history.js";
// type HistoryEntry: Ye TypeScript ko batata hai ki database se jo purane messages aayenge, unka structure kaisa hoga. Usme ek sender hoga (User/AI), ek body (message text) hoga, aur shayad ek timestamp hoga. Ye blueprint ensure karta hai ki hmari file mein koi galat kachra na aa jaye.

// buildHistoryContextFromEntries: AI models (jaise Claude ya GPT-4) ko history ek specific format mein chahiye hoti hai. Wo database ki raw JSON nahi samajhte. Ye function un saare messages ko leta hai, aur unke aage-peeche tags lagata hai. Jaise:
// <history>
// User: Hi
// Assistant: Hello!
// </history>





import { extractTextFromChatContent } from "../shared/chat-content.js";
// Aaj kal ke LLMs bohot smart hain. User sirf text nahi bhejta, wo images aur PDFs bhi bhejta hai. Toh backend mein message sirf ek simple string "hello" nahi hota. Wo ek complex array hota hai: [{ type: "text", text: "hello" }, { type: "image_url", url: "..." }].
// Ye imported function tere system ka "Filter/Juicer" hai. Iska ek hi kaam hai: Us complex array (ya object) ke andar ghusna, usme se sirf aur sirf padhne laayak (readable) text nikalna, aur baaki image/file data ko wahan se hata dena.





export type ConversationEntry = {
  role: "user" | "assistant" | "tool";
  entry: HistoryEntry;
};




// 🐛 The Problem: The Multimodal Trap
// Purane zamaane mein (matlab 2 saal pehle), chat bots sirf text lete the. Frontend backend ko bhejta tha:
// body = "Hello AI, how are you?"

// Par aajkal Claude 3.5, GPT-4o ka zamaana hai. Log text ke saath images aur PDFs bhi bhejte hain (Multimodal). Toh ab frontend sirf string nahi bhejta, wo ek Array of Objects bhejta hai:
// body = [{ type: "text", text: "Hello AI" }, { type: "image_url", url: "https://..." }]

// Ab JavaScript ki sabse badi galti kya hai? Agar tu is array ko kisi string ke andar ghusane ki koshish karega (jaise `User said: ${body}`), toh JavaScript function fail nahi hota, wo chup-chaap array ko string mein badal deta hai aur output deta hai:
// 👉 "User said: [object Object]"

// Soch, agar tera system AI ko ye history bhej de ki "User said: [object Object]", toh AI bilkul hallucinate kar jayega aur bolega "I cannot understand what you mean by [object Object]". Tera Xorthax ka poora chat experience barbaad ho jayega!
/**
 * Coerce body to string. Handles cases where body is a content array
 * (e.g. [{type:"text", text:"hello"}]) that would serialize as
 * [object Object] if used directly in a template literal.
 */
function safeBody(body: unknown): string {
  // Type unknown: TypeScript mein unknown ka matlab hai "Mujhe nahi pata ye kya kachra hai, ye string bhi ho sakti hai, array bhi ho sakta hai, ya null bhi." Ye developer ko force karta hai ki bina check kiye isko use mat karna.


  // Step 1: The Fast Path. System pehle check karta hai ki kya user ne sirf ek normal text message bheja tha? Agar haan, toh faaltu processing mat karo, seedha us string ko return kar do. Ye CPU cycles bachata hai.
  if (typeof body === "string") {
    return body;
  }

  // Agar wo string nahi thi (matlab wo wahi complex Multimodal Array tha jisme image/text mix hain), toh usko us dusre function extractTextFromChatContent ke andar daal do.
  // Ye function us array ke andar ghusega, dhoondhega ki "text" kahan likha hai, aur sirf us text ko bahar nikal laayega, baaki images/files ko ignore kar dega (kyunki LLM prompt mein sirf text ki formatting ho rahi hai yahan).
  // The Ultimate Safety Net (?? ""): Ye jo double question mark hai isko Nullish Coalescing kehte hain. Agar array itna kharab tha ki usme koi text tha hi nahi (sirf ek image thi), toh extract function null return karega. Ye ?? "" us null ko ek khali string "" mein badal dega taaki tera aage ka code crash na ho.
  return extractTextFromChatContent(body) ?? "";
}







// Iska ek hi mission hai: Database se aayi hui raw chat history ko uthao, uski safai karo, aur usko ek aise perfect text format mein badal do jise padh kar AI (LLM) bilkul confuse na ho.
export function buildAgentMessageFromConversationEntries(entries: ConversationEntry[]): string {

  // Agar chat history ekdum khali hai, toh chup-chaap khali string de do. Fail-fast mechanism.
  if (entries.length === 0) {
    return "";
  }


  // Prefer the last user/tool entry as "current message" so the agent responds to
  // the latest user input or tool output, not the assistant's previous message.
  // Yha pr hum sbse latest message dhund rhe hain jo user ne bheja tha ya jo kisi tool ne bheja tha ai ko. agr hum seedha yha pr sbse last message lelete toh problem ho jati, kyuki last message ai ka bhi ho skta h jo, network issue ki wajah se beech m hi ruk gya tha, agr hum yhi utha kr phirse ai ko dedengey toh ai hallucinate krne lgega.   
  let currentIndex = -1;
  for (let i = entries.length - 1; i >= 0; i -= 1) {
    const role = entries[i]?.role;
    if (role === "user" || role === "tool") {
      currentIndex = i;
      break;
    }
  }
  if (currentIndex < 0) {
    // "Bhai, agar kuch samajh na aaye, toh chup-chaap jo sabse aakhri message hai (length - 1), usi ko utha lo aur aage badho.
    currentIndex = entries.length - 1;
  }


  // Pichle loop ne dhoondh nikala tha ki "Current Message" (wo aakhri sawal ya tool result jiska AI ko jawab dena hai) kahan rakha hai (currentIndex). Ab ye code us index ka use karke poori chat history ke do tukde (Past aur Present) kar raha hai aur unhe AI ke khane laayak (digestible) format mein pack kar raha hai.
  // Jo index pichle reverse loop ne dhundha tha, us index ka actual message currentEntry variable mein nikal liya.     
  const currentEntry = entries[currentIndex]?.entry;
  if (!currentEntry) {
    return "";
  }

  // Kya ho raha hai: Ye is code ka sabse elegant hissa hai. Array ka .slice(0, currentIndex) function 0 se lekar current message ke theek pehle tak ke saare messages ko kaat kar alag kar leta hai.
  // Concept: Is ek line ne tere data ke do hisse kar diye. Jo current index pe tha, wo tera Present (Current Task) ban gaya. Aur jo usse pehle ka tha, wo tera Past (History Context) ban gaya.
  const historyEntries = entries.slice(0, currentIndex).map((e) => e.entry);

  // Kya ho raha hai: System check kar raha hai ki kya ye user ka bilkul pehla message hai? (Yani pichli koi history nahi hai).

  // SDE-1 Insight: Ek Junior dev andhon ki tarah history format karne wala function chala deta jisse AI ke paas khali tags <history></history> chale jaate. OpenAI aur Claude har ek extra character (token) ka paisa charge karte hain.

  // Ye if condition tera bill bachati hai! Agar history zero hai, toh faltu ki formatting mat karo, bas safeBody se message ko clean karo (taaki [object Object] na aaye) aur direct LLM ko bhej do.
  if (historyEntries.length === 0) {
    return safeBody(currentEntry.body);
  }



  // formatEntry ek chhota sa arrow function (helper) hai. 
  // Iska kaam hai har message ko ek standard shakal dena: 
  // Sender: Message. Jaise: "User: What is the weather?" ya "Assistant: It is raining."
  const formatEntry = (entry: HistoryEntry) => `${entry.sender}: ${safeBody(entry.body)}`;

  // Ab yeh saara saaman ek doosre function buildHistoryContextFromEntries ko pass kar diya gaya.
  // Isme saari history aur current message ek array mein jod kar bhej diye [...historyEntries, currentEntry].
  // currentMessage ko specifically format karke bheja.
  // Aur formatEntry tool bhi bhej diya taaki wo doosra function baaki messages ko bhi format kar sake.
  return buildHistoryContextFromEntries({
    entries: [...historyEntries, currentEntry],
    currentMessage: formatEntry(currentEntry),
    formatEntry,
  });
}
