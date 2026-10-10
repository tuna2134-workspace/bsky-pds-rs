import { encode } from '@atproto/lex-cbor'
const res = await fetch('https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur/log/audit').then(r => r.json())
const op = res[res.length - 1].operation
const { sig, ...unsigned } = op
console.log(Buffer.from(encode(unsigned)).toString('hex'))
