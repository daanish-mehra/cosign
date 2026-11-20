// QuickNode Streams filter (Solana devnet, Block dataset).
// Keeps only transactions that touch Cosign's agent wallet, vault or multisig,
// and passes along the token balance changes so the webhook can spot outflows.
function main(stream) {
  const WATCH = [
    "FWSr834EBvutn9dgqz5kSXtYS7KhKgyE83AQCcCqJLty", // agent wallet (single signer)
    "8saBb35QzMwz9MFUscMrFxn1tmY8MQ8rrgknNGQ5RYG2", // Cosign guarded vault
    "59FdRZ25hWj2JMzTbwrUib37bfKBAWiv3Bcr9ktKfUfn", // 2 of 2 multisig
  ];
  const USDC = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
  const blocks = Array.isArray(stream.data) ? stream.data : [stream.data];
  const hits = [];
  for (const block of blocks) {
    if (!block || !block.transactions) continue;
    for (const tx of block.transactions) {
      const text = JSON.stringify(tx);
      const touched = WATCH.filter(a => text.includes(a));
      if (!touched.length) continue;
      const meta = tx.meta || {};
      const keys = ((tx.transaction || {}).message || {}).accountKeys || [];
      hits.push({
        signature: ((tx.transaction || {}).signatures || [])[0] || null,
        slot: block.slot != null ? block.slot : (block.parentSlot != null ? block.parentSlot + 1 : null),
        blockTime: block.blockTime || null,
        touched,
        err: meta.err || null,
        signers: keys.filter(k => k && k.signer).map(k => k.pubkey || k),
        usdc: { pre: (meta.preTokenBalances || []).filter(b => b.mint === USDC), post: (meta.postTokenBalances || []).filter(b => b.mint === USDC) },
      });
    }
  }
  return hits.length ? { hits } : null;
}
