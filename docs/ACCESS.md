# Getting working model access (official routes only)

Researched 2026-10-24. Secondary sources and forum posts are marked; verify in the consoles.
Only sign up in your own name. Never use keys found online or anyone else's account.

## 1. NVIDIA API catalog (build.nvidia.com): for development
- **Route:** join the free NVIDIA Developer Program, open build.nvidia.com, pick a model, click
  **Get API Key**. NVIDIA says Developer Program members get free NIM API access for prototyping.
  https://developer.nvidia.com/blog/access-to-nvidia-nim-now-available-free-to-developer-program-members/
  https://docs.api.nvidia.com/nim/docs/product
- **Card:** none mentioned in the official docs. Phone verification is commonly reported (forum).
- **Credits:** conflicting. Older posts say 1,000 credits at sign-up; newer posts and DevRel say
  the credit system was removed. Check the account page (top right of build.nvidia.com).
- **Rate limit:** about 40 RPM is the figure repeated in forum threads. NVIDIA's own docs only
  say limits vary per model and load, and are meant for evaluation. A moderator said there is
  no official way to raise it on the free tier. Increase requests on the forum are user posts.
  https://forums.developer.nvidia.com/t/request-for-nvidia-build-api-rate-limit-increase-40-rpm-200-rpm/377433
- **Nemotron models on the catalog** (from `GET https://integrate.api.nvidia.com/v1/models`,
  which works without a key; 85 models listed on 2026-10-24):
  `nvidia/nemotron-3-super-120b-a12b`, `nvidia/nemotron-3-ultra-550b-a55b`,
  `nvidia/nemotron-nano-3-30b-a3b`, `nvidia/nemotron-3.5-lightning-30b-a3b`,
  `nvidia/nemotron-3.5-bolt-e4b`, `nvidia/llama-3.1-nemotron-ultra-253b-v1`,
  `nvidia/llama-3.1-nemotron-70b-instruct`, plus safety/embedding/parse variants.
  Being listed does not mean the model is callable for your key; `redline models` tests that.
- **Implication:** at ~40 RPM the audit loop must be rate-aware (Redline's LLM client retries
  on 429 with backoff). Fine for dev, not for the final run.

## 2. Nebius Token Factory: required for the submission
- **Sign up:** https://tokenfactory.nebius.com (Google/GitHub/Microsoft login, contact details,
  terms, then billing). https://docs.nebius.com/signup-billing/sign-up
- **Card:** the Token Factory billing page says "Setting up a billing account requires a bank
  card." Bank transfer is for companies only, via a proforma invoice from Nebius sales.
  Cards: first charge is $25, added to your balance. Individuals and companies can both pay by
  card. https://docs.tokenfactory.nebius.com/other-capabilities/billing-new
  https://docs.nebius.com/signup-billing/payments/card
- **Supported billing countries:** not published in the pages I could read. Builder Program terms
  say all registrations go through country-based screening and sanctions checks.
- **Trial credit:** $1 for 30 days on new accounts (billing page).
- **Promo codes:** Token Factory: balance, **Top up**, **With promo code**, enter code. One
  Token Factory page says a code can be applied without a card; the general Nebius AI Cloud
  promo page says payment details must be on file first ("Apply promo code" button missing
  until then). These disagree: try the Token Factory flow first.
  https://docs.tokenfactory.nebius.com/other-capabilities/billing-new
  https://docs.nebius.com/signup-billing/payments/promo-codes
- **Your code (NEBIUS-DEVPOST-GLOBAL26):** I could not verify it from public pages. Redeem it
  as above. Codes expire and cannot pay outstanding invoices.
- **Builder Program:** free membership. Registration gives two promo codes: USD 25 Token
  Factory credits and USD 25 Tavily credits (a second USD 25 Nebius credit about 30 days after
  verification, per the earlier terms listing). Credits expire 90 days after issue, for
  prototyping only. Corporate/edu emails are preferred, disposable emails are blocked, one
  account per verified email, possibly one signup per IP per 24h. Card requirement not stated.
  https://nebius.com/builders-terms-and-conditions
  https://dev.nebius.com/
- **Blocked onboarding, who to contact:**
  - Hackathon FAQ / Discord (community channel; the best place for hackathon-specific credit
    or onboarding help; ask the organisers directly). Find the invite on the Devpost page.
  - Nebius support: ticket from the support center, or email support@nebius.com if you cannot
    reach the console. Use a personal email, not a shared mailbox.
    https://docs.nebius.com/overview/support
  - Token Factory feedback: contree@nebius.com (from the Token Factory docs).
  Suggested message: "Card declined at onboarding for Token Factory (country: <yours>, card
  type: <debit/credit/virtual>). Hackathon participant, Nebius x NVIDIA Global AI Hackathon.
  Can you activate promo NEBIUS-DEVPOST-GLOBAL26 or advise an alternative payment route?"
- **Card tips (general, not from Nebius docs):** try a different card, ask the bank to allow
  international/online payments and 3-D Secure, avoid prepaid cards.

## 3. Other official Nebius routes that count as "runs on Nebius"
- **Nebius AI Cloud** (the GPU cloud, https://nebius.com): same account system and billing
  (card, $25 first charge; companies may use bank transfer). Running an open model yourself on
  Nebius GPUs would satisfy "runs on Nebius AI Cloud" per the hackathon wording (Luca Berton
  summary; confirm against the official Devpost rules). It still needs billing, so it does not
  avoid the card problem.
- **Builder Program credits** apply to Token Factory and are the likeliest card-free-ish route.
- Ask the organisers whether credit-granting or an alternative onboarding path exists. This is
  the one route I would not try to work around myself.

## Not done, by design
No third-party keys, shared accounts, or key lists were searched for or used.
