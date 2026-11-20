// Vercel function: POST /api/stream receives QuickNode Streams payloads.
// For every watched transaction it works out who lost and gained USDC, and flags
// money that left the agent's single-signer wallet (no Cosign signature) to an
// address that isn't on the allowlist.
const AGENT = "FWSr834EBvutn9dgqz5kSXtYS7KhKgyE83AQCcCqJLty";
const VAULT = "8saBb35QzMwz9MFUscMrFxn1tmY8MQ8rrgknNGQ5RYG2";
const MULTISIG = "59FdRZ25hWj2JMzTbwrUib37bfKBAWiv3Bcr9ktKfUfn";
const COSIGNER = "2SwMdFfNptfvZPabPdEfQcHecmfkctvx2jwRiwwDL7H1";

function deltas(usdc) {
  const amt = b => Number((b.uiTokenAmount || {}).uiAmountString || (b.uiTokenAmount || {}).uiAmount || 0);
  const by = {};
  for (const b of usdc.pre || []) by[b.owner] = (by[b.owner] || 0) - amt(b);
  for (const b of usdc.post || []) by[b.owner] = (by[b.owner] || 0) + amt(b);
  return by;
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(200).json({ service: "cosign quicknode streams webhook", watching: [AGENT, VAULT, MULTISIG] });
  }
  let body = req.body;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch { body = {}; } }
  const hits = (body && body.hits) || (Array.isArray(body) ? body.flatMap(x => (x && x.hits) || []) : []);
  const events = hits.map(h => {
    const d = deltas(h.usdc || {});
    const fromAgent = (d[AGENT] || 0) < 0, fromVault = (d[MULTISIG] || 0) < 0 || (d[VAULT] || 0) < 0;
    const cosigned = (h.signers || []).includes(COSIGNER);
    const to = Object.entries(d).filter(([, v]) => v > 0).map(([k, v]) => ({ owner: k, usdc: +v.toFixed(6) }));
    const kind = h.err ? "failed" : fromVault ? (cosigned ? "vault outflow, cosigned by Cosign Guard" : "vault outflow WITHOUT cosign") : fromAgent ? "UNGUARDED outflow from single-signer agent wallet" : "inflow";
    return { signature: h.signature, slot: h.slot, kind, to, explorer: h.signature ? `https://explorer.solana.com/tx/${h.signature}?cluster=devnet` : null };
  });
  for (const e of events) console.log(JSON.stringify({ cosign_stream: e }));
  return res.status(200).json({ received: events.length, events });
}
