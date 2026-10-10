import { verifySignature } from '@atproto/crypto'
import { encode } from '@atproto/lex-cbor'
import { sha256 } from '@atproto/crypto'
const res = await fetch('https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur/log/audit').then(r => r.json())
const op = res[res.length - 1].operation
const { sig, ...unsigned } = op
const bytes = encode(unsigned)
const digest = await sha256(bytes)
const sigBytes = Buffer.from(sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
const prevRot = res[res.length - 2]?.operation?.rotationKeys ?? op.rotationKeys
for (const rk of prevRot) {
  try {
    const ok = await verifySignature(rk, new Uint8Array(digest), new Uint8Array(sigBytes))
    console.log(rk.slice(-10), ok ? 'VALID' : 'invalid')
  } catch (e) { console.log(rk.slice(-10), 'ERR', e.message) }
}
