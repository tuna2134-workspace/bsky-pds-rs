import { Secp256k1Keypair } from '@atproto/crypto'
import { encode, decode } from '@atproto/lex-cbor'

// 1. What does the REFERENCE encoder produce for an unsigned PLC op?
const unsigned = {
  type: 'plc_operation',
  rotationKeys: ['did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg'],
  verificationMethods: { atproto: 'did:key:zQ3shQo6TF2moaqMTrUZEM1jeuYRQXeHEx4evX9751y2qPqRA' },
  alsoKnownAs: ['at://bsky.app'],
  services: { atproto_pds: { type: 'AtprotoPersonalDataServer', endpoint: 'https://x.test' } },
  prev: null,
}
const bytes = encode(unsigned)
console.log('REF UNSIGNED:', Buffer.from(bytes).toString('hex').slice(0, 120))
// key order?
console.log('KEYS:', Object.keys(decode(bytes)));
