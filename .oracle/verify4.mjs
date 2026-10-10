import { verifySignature } from '@atproto/crypto'
import { encode } from '@atproto/lex-cbor'
const res = await fetch('https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur/log/audit').then(r => r.json())
const op = res[res.length - 1].operation
const { sig, ...unsigned } = op
const bytes = encode(unsigned)
const sigBytes = Buffer.from(sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
const prevRot = res[res.length - 2]?.operation?.rotationKeys ?? op.rotationKeys
for (const rk of prevRot) {
  try {
    const ok = await verifySignature(rk, bytes, Buffer.from(sigBytes))
    console.log(rk.slice(-10), ok ? 'VALID' : 'invalid')
  } catch (e) { console.log(rk.slice(-10), 'ERR', e.message) }
}
// also: what does the reference encoder produce for the full signed op? (CID check)
import { CID } from 'multiformats/cid'
import { sha256 as hasher } from 'multiformats/hashes/sha2'
const signedBytes = encode(op)
const h = await hasher.digest(signedBytes)
const c = CID.createV1(0x71, h)
console.log('computed op CID:', c.toString(), 'audit says:', res[res.length-1].cid)
