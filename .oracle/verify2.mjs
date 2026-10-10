import { Secp256k1Keypair } from '@atproto/crypto'
import { encode } from '@atproto/lex-cbor'
const res = await fetch('https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur/log/audit').then(r => r.json())
const op = res[res.length - 1].operation
const { sig, ...unsigned } = op
const bytes = encode(unsigned)
const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
const sigBytes = Buffer.from(sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
// rotation key from previous op
const prevRot = res[res.length - 2]?.operation?.rotationKeys ?? op.rotationKeys
let okAny = false
for (const rk of prevRot) {
  try {
    const key = await Secp256k1Keypair.fromDid(rk)
    const ok = await key.verify(Buffer.from(digest), sigBytes)
    console.log(rk.slice(-10), ok ? 'VALID' : 'invalid')
    okAny ||= ok
  } catch (e) { console.log(rk.slice(-10), 'ERR', e.message) }
}
console.log('ANY:', okAny)
