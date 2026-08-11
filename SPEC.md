# The @@ protocol — puzzle mail

**Wire specification, version DAE-5.**
Revision of 11 August 2026.

> Licence: **CC BY 4.0**. See the end of this document.
> This is the *specification*. The reference code is MIT and lives elsewhere;
> the two are separate on purpose, and the reason is at the end too.

---

## 0. What this is, in one paragraph

An ordinary encrypted mail travels as one object. Whoever intercepts it
holds the whole thing and only needs the key — today, or in twenty years.
The @@ protocol splits every message into two pieces that travel by
different routes: a small **eHead** goes through the mail system as an
attachment, and a large **eBody** stays on the sender's server and is
fetched over HTTPS when the message is read. Neither piece is usable
alone, and that is a property of the construction, not a promise.

Addresses with one `@` are ordinary mail. Addresses written with `@@`
select this protocol.

### What it does not do

Say this plainly wherever you implement it, because a reader who finds it
out later stops believing the rest:

- **X25519 and Ed25519 do not resist a quantum computer.** Neither does
  RSA. The defence against "copy today, decrypt tomorrow" is not the
  asymmetric algorithm: it is that the two pieces do not travel together,
  and that the stored piece can be made to expire.
- **Missing a few bytes is not missing a piece.** The all-or-nothing
  transform is real, but an attacker holding the eHead and an eBody short
  by two bytes recovers the message in under a second by trying the
  65 536 possibilities. What protects is the 10/90 split — that the
  interceptor lacks 90% of the data — not the mask.
- **Whoever serves the key directory can substitute a key.** Section 8
  says what to do about it, and it is not enough on its own.
- **A recipient's mailbox is not protected by the puzzle.** Whoever gets
  into it holds the eHead and the key. That is what the PIN in section 5
  is for.

---

## 1. Terms

| Term | Meaning |
|---|---|
| **eBlock** | The whole encrypted message, before splitting. |
| **eHead** | JSON object with the parameters and the first slice of ciphertext. Travels as a mail attachment. |
| **eBody** | The remaining ciphertext. Stored by the sender's server, fetched over HTTPS. |
| **bodyId** | 32 random bytes, written as 64 lowercase hex characters. Locates the eBody. |
| **origin** | Domain of the server holding the eBody. |
| **carrier** | The ordinary mail that carries the eHead. |

The key words MUST, MUST NOT, SHOULD and MAY are used in the sense of
RFC 2119.

---

## 2. Keys

Every participant has two key pairs:

| Purpose | Algorithm | Public key |
|---|---|---|
| Key agreement | X25519 | 32 raw bytes |
| Signing | Ed25519 | 32 raw bytes |

Public keys are exchanged and published as **raw bytes in lowercase
hex**, never PEM. A curve key is 32 bytes; wrapping it in DER made it
look like RSA and bought nothing.

A key's **fingerprint** is `SHA-256(public key bytes)`, 64 lowercase hex
characters. Implementations MUST derive it exactly this way, or two
implementations will disagree about whether a contact's key changed.

Implementations MUST reject an X25519 public key whose shared secret
comes out all zeroes: that is a small-order point chosen so the result is
predictable.

---

## 3. Sealing an eBlock

Input: the complete message as RFC 5322 MIME, the recipients' X25519
public keys, an origin domain, and a PIN (section 5).

```
1.  k     = 32 random bytes
    iv    = 12 random bytes

2.  ciphertext, tag = AES-256-GCM(k, iv, plaintext)      tag is 16 bytes
                                                          no associated data

3.  aontMask = SHA-256( "DAE-AONT-v2" || ciphertext )     32 bytes
    k'       = k XOR aontMask

4.  bodyId  = 32 random bytes

5.  pinMask = PBKDF2-HMAC-SHA256( PIN, salt = bodyId, N, 32 bytes )
    k'      = k' XOR pinMask

6.  for each recipient public key P:
        payload   = k'(32) || bodyId(32) || len(origin)(1) || origin
        envelope  = ECIES(payload, P)                     see section 4
        arrEncKeys[ fingerprint(P) ] = base64(envelope)

7.  blockSize = length(ciphertext)
    headSize  = min( floor(blockSize * 0.10), 102400 )
    headSize  = max( 1, min(headSize, blockSize - 1) )

    headPayload = ciphertext[ 0 : headSize ]
    eBody       = ciphertext[ headSize : ]
```

`bodyId` is carried and stored as its 64-character lowercase hex form,
but is used **raw (32 bytes)** as the PBKDF2 salt and inside the
envelope. Getting this wrong is the single most common way two
implementations stop agreeing.

Step 7 MUST NOT put the entire block in the head: `headSize` is always at
least one byte short of `blockSize`. A message whose eBody is empty is
not puzzle mail.

### 3.1 The eHead

A JSON object, serialised without escaping forward slashes:

```json
{
  "szVersion":  "DAE-5",
  "szAlgo":     "A256GCM+X25519+AONT+PIN+ORIGIN",
  "szIv":       "<base64, 12 bytes>",
  "szTag":      "<base64, 16 bytes>",
  "nPinIter":   1,
  "nBlockSize": 123456,
  "nHeadSize":  12345,
  "arrEncKeys": { "<fingerprint hex>": "<base64 envelope>" },
  "szPayload":  "<base64 of headPayload>"
}
```

**There is deliberately no checksum of the ciphertext.** A digest of the
complete ciphertext is *exactly* the value that removes the all-or-nothing
mask; publishing it in the piece that travels by mail would reduce the
transform to nothing. Integrity comes from the GCM tag, which covers the
whole message. An implementation that adds a convenience checksum here
breaks the protocol's only reason to exist.

`nPinIter` travels in the header rather than living in code so the cost
can be raised later without making already-delivered mail unreadable.
Readers MUST accept the value from the header and SHOULD reject values
outside 1 … 10 000 000.

### 3.2 Opening

```
1.  Find the entry in arrEncKeys matching a fingerprint you hold a
    private key for. Open the envelope; recover k', bodyId, origin.
2.  Fetch the eBody (section 7). ciphertext = headPayload || eBody.
3.  Verify length(ciphertext) == nBlockSize. If not, stop.
4.  k = k' XOR SHA-256("DAE-AONT-v2" || ciphertext)
          XOR PBKDF2(PIN, bodyId, nPinIter, 32)
5.  plaintext = AES-256-GCM-decrypt(k, iv, ciphertext, tag)
```

If the tag does not verify, the implementation cannot tell a wrong PIN
from a damaged message, and MUST NOT claim to. Both fail identically, and
that indistinguishability is deliberate: a message that announced "wrong
PIN" would confirm to an attacker that the PIN is what stands between
them and the text.

---

## 4. The key envelope (ECIES over X25519)

```
eph_priv, eph_pub = fresh X25519 pair, per message AND per recipient

shared = X25519(eph_priv, recipient_pub)
kek    = HKDF-SHA256( ikm  = shared,
                      salt = eph_pub || recipient_pub,
                      info = "DAE-3-KEK",
                      len  = 32 )

nonce  = 12 random bytes
sealed = AES-256-GCM(kek, nonce, payload)          16-byte tag appended

envelope = eph_pub(32) || nonce(12) || sealed
```

The `info` string still reads `DAE-3-KEK` for the reason such strings
exist: it is a domain separator, and changing it to match the version
number would break every already-delivered message for no gain.

On opening, the payload MUST be parsed strictly:

```
k'(32) || bodyId(32) || nLen(1) || origin(nLen bytes, ASCII)
```

and discarded if the total length is not exactly `65 + nLen`. `nLen` is
at most 253.

---

## 5. The PIN

The message key is **always** derived through a PIN. When the sender sets
none, the PIN is the string `000000` and `nPinIter` is `1`.

There is one encryption path, not two. Two paths mean the rarer one is
exercised less, tested less, and is the one that eventually breaks.

| | PIN | nPinIter |
|---|---|---|
| No second channel | `000000` | 1 |
| Sender chose one | 6 digits, or a passphrase of 12–128 characters | 600000 |

**A PIN of `000000` protects nothing.** It is public, it is written here,
and anyone reading any implementation knows it. It simplifies the format
and that is all it does. From which follows a rule an implementation MUST
NOT break:

> An interface MUST NOT tell the user a message is "PIN protected" when
> the PIN is the default one.

Telling them otherwise leaves someone trusting a protection they do not
have, which is worse than no protection, because they stop looking for
another.

The PIN travels by some channel other than the mail — spoken, texted,
handed over. If it travelled with the message it would protect nothing.

**Rate limiting does not protect the PIN, and implementations should stop
claiming it does.** Whoever downloads the eBody once tries every
combination at home without speaking to any server again. Six digits are
a million combinations and an ordinary graphics card exhausts them in
about ninety seconds. What defends the PIN is that both pieces are needed
before the attempt can begin, and that each attempt costs. A generated
passphrase of five words from a 256-word list is 40 bits — a million
times more work. A passphrase *chosen by a person* is usually worse than
the six digits, because a dictionary finds it first.

---

## 6. The carrier mail

The eHead is attached to an ordinary mail:

| | |
|---|---|
| Filename | `message.ehead` |
| MIME type | `application/x-dae-ehead` |
| Subject | `@@ <local-part> <domain> <8 hex uppercase>` |

Recipients recognise puzzle mail **by the attachment, never by the
subject or the sender's domain** — the same code path must handle mail
from any server.

An implementation MUST NOT display the carrier subject or the carrier
body where the message's own subject and body go. The carrier subject is
a reference string, and the carrier body is a courtesy line written by
the sender's server; neither is what anybody wrote. Showing them tells
the reader that this is their correspondent's message, and it is not.

The subject announces a domain, so it can be compared against the real
sender to catch a mail dressed up as @@ from a domain it did not come
from. This is **not** authentication — a subject is text and anyone can
write anything in it. Authorship is proved by the signature in section 9;
envelope authenticity by SPF, DKIM and DMARC.

---

## 7. Fetching the eBody

```
GET https://<origin>/ebody/<bodyId>
```

`<bodyId>` is 64 lowercase hex characters and MUST be validated against
`^[0-9a-f]{64}$` before it reaches any storage layer.

Response on success: `200`, `application/octet-stream`, the raw bytes,
with `Access-Control-Allow-Origin: *` so a browser on another domain can
implement the protocol.

Servers:

- MUST rate-limit per bodyId and per network prefix, and answer `429`
  with `Retry-After` when exceeded.
- MUST answer `404` identically whether the piece never existed or has
  expired.
- MUST NOT log the requester's address against the bodyId. The counter
  exists to warn the message's owner that a piece is being pulled
  repeatedly; turning it into a record of who read what would make the
  server exactly the thing this protocol exists to avoid.

Clients fetching from a **foreign** origin:

- MUST validate the domain before contacting it: no bare IP addresses, no
  ports, no paths, no reserved or private TLDs.
- MUST use HTTPS with certificate verification on, and MUST NOT follow
  redirects.
- MUST set a timeout and a maximum response size. An unknown domain is a
  server you do not control.
- MUST NOT keep a copy of a foreign piece, not even briefly. The clock
  belongs to the sender: if their server deletes it, the message has to
  stop being readable here too. A cache turns "it is deleted when I say
  so" into "…except on every server it passed through", which cannot be
  promised to anyone.

Distinguish the failures when telling the reader, because the only
question they have is "does this come back?" and the answer differs: no
answer or slow (maybe later), `404` (never), certificate refused (we
refused, and why), `429` (we asked too often), wrong bytes (altered or
incomplete), local failure (our problem, not theirs). Offer a retry only
for the failures that waiting fixes.

---

## 8. The key directory

```
GET https://<domain>/.well-known/dae/hu/<hu>
```

where `hu = z-base32( SHA-1( lowercased local-part ) )`, 32 characters,
using the WKD alphabet `ybndrfg8ejkmcpqxot1uwisza345h769`. The domain is
not hashed in: the server being asked already knows it.

Queries carry the **digest of an address, never the address**, so the
directory cannot be walked and nobody harvests a domain's users. This is
the mechanism OpenPGP uses for WKD, and it produces the same result as
their official test vector, so a client that already speaks WKD can ask
without changing anything.

Response `200`, `text/plain`, `Access-Control-Allow-Origin: *`:

```
curve <64 hex>
sign <64 hex>
```

with the X25519 fingerprint in an `X-DAE-Fingerprint` response header.

Servers MUST:

- return the **same 404** whether the address does not exist or exists
  without a published key;
- make every response take a minimum fixed time (120 ms is enough), or
  the clock enumerates what the digest hides;
- rate-limit per network prefix.

### 8.1 The part that is not solved by any of this

**Whoever serves the directory can hand out a key of their own and read
everything.** The mail would be encrypted correctly — for someone else.
Against that, neither the encryption nor the two-piece split helps at
all.

The mitigation is trust on first use, and implementations SHOULD do it:

- Remember a correspondent's key the first time you write to them.
- If a later send finds a different key, **stop the send.** Show both
  fingerprints grouped in fours so they can be compared by eye or read
  out over the phone, and ask for confirmation.
- Remember the new key **after** a successful send, never before. If
  checking wrote the key, the second check would say everything was fine
  and the change would never be seen again.
- Tie the confirmation to those exact fingerprints, so an "I accept"
  given for an innocent change cannot be replayed tomorrow for a
  different key.
- **Do not accuse.** Almost always the change is innocent — someone lost
  their key and made another. A warning that frightens without explaining
  gets ignored within a fortnight, and then it is worth nothing.

Publish the fingerprint over a second channel so it can be checked
against something that did not come from the same server.

---

## 9. Signatures

The signature goes **inside** the encryption. Outside, it would announce
who wrote the message to anyone watching.

The signed envelope, which is what gets encrypted:

```
DAE-SIG1
{"szAlgo":"Ed25519","szSigner":"...","szSignerFp":"...","szSignature":"..."}
<blank line>
<raw MIME>
```

The JSON is one line. `szSignature` is base64 of the 64-byte Ed25519
signature over the raw MIME that follows. `szSignerFp` is the signer's
**X25519** fingerprint — the one a person can check by another channel.

A missing signing key degrades to "sent unsigned", never to "not sent",
and the recipient MUST be told it arrived unsigned rather than shown
nothing.

Implementations MUST import the private key separately for decryption and
for signing, and MUST NOT reuse one key object for both. WebCrypto
refuses to, and it is right: separating what each key is for defeats
attacks that get someone to sign something they believed they were
decrypting.

Ed25519 falls to Shor exactly as RSA does. What the all-or-nothing
transform protects is the content, not the authorship.

---

## 10. Retention and the read notice

The sender chooses how long the stored piece lives: permanent, expiring
after a period, or destroyed once read.

This matters more than it looks, and for a reason worth writing into any
implementation's interface: once the stored half is deleted, whoever
copied the other half that day can never assemble the two — not by
waiting twenty years, not with a quantum computer. What they lack is not
a hard calculation, it is data that has stopped existing. And while that
half is stored, the server holding it is a place worth robbing; when it
expires, it stops being one.

"Destroyed on reading" cannot be implemented by asking the reader's
server to say so, because a bare "I have read it" from anyone who
intercepted the eHead would be an unauthenticated remote delete — a
destruction button. The proof of reading is derived from the recovered
key:

```
token  = SHA-256( "DAE-READ-1" || k || bodyId )
digest = SHA-256( token )
```

`k` is the 32 raw key bytes; `bodyId` is its 64-character lowercase hex
**text**; `token` is hashed in its own lowercase hex text form. The
sender's server stores only `digest`. The reader sends `token` to
`POST /ebody/read`. The server hashes what it receives and compares in
constant time.

Only someone who recovered `k` can compute it — which needs both complete
pieces, the private key and the PIN: the same three things reading needs.
Not the interceptor of the eHead, not whoever downloaded the piece, not
the server.

The endpoint MUST answer `204` in every case. A bad token, an invented
locator and a message with no stored proof must be indistinguishable from
outside, or the endpoint becomes an oracle for which locators exist —
and the locator is the eBody's credential.

**The deadline still governs.** The notice only brings it forward. If the
other server stays silent, crashes or lies, the piece dies by its
deadline anyway. Ephemeral retention across domains will always rest on
the deadline, and an implementation MUST NOT remove it on the grounds
that the notice exists.

---

## 11. Conformance

An implementation is conformant if, for the same inputs, it produces an
eBlock that every other conformant implementation opens byte for byte,
and opens theirs. Nothing else counts. The reference implementations are
cross-checked against each other by a test that seals with each and opens
with all the rest, with and without a PIN.

The checks worth copying:

- Seal with A, open with B, for every ordered pair.
- Remove one byte from the eBody: nothing must open.
- Give an attacker the whole eBody **and the private key**, with no
  eHead: nothing must be recoverable. This is the check that holds up
  "not even we can read it", and it is the one most often missing.
- A multipart boundary containing uppercase letters must survive. Folding
  the `Content-Type` header to lowercase before extracting the boundary
  leaves every multipart mail with no body and no attachments, and it is
  a bug that comes back.
- Line endings are CRLF. A MIME message with Unix line endings is
  invalid, and almost everything tolerates it, which is why it is only
  found much later.

---

## Licence

Copyright © 2026 doubleat.email

This specification is licensed under the
**Creative Commons Attribution 4.0 International licence (CC BY 4.0)**.

You may copy, redistribute, adapt and build upon this document for any
purpose, including commercially, provided you give appropriate credit and
indicate whether changes were made.

Full text: <https://creativecommons.org/licenses/by/4.0/legalcode>
Summary: <https://creativecommons.org/licenses/by/4.0/>

### Why the document and the code have different licences

The reference implementations are MIT. The specification is CC BY 4.0.
They are different things and they need different permissions.

MIT is a software licence: it speaks of "the Software", of copies and of
substantial portions. Applying it to a document leaves anyone who wants
to quote a paragraph in a standards draft, a paper or a competing
implementation's manual asking their lawyer what it means. CC BY is the
licence written for documents, it is what everyone uses for standards,
and it says without ambiguity that this can be copied, quoted, translated
and built upon.

A specification nobody can quote without hesitation is not a
specification. It is documentation for one product.

Neither licence grants patent rights. MIT does not include a patent
grant; if that ever matters, Apache 2.0 does.

**Not "public domain."** Spanish law, which is where this is written,
does not allow an author to renounce copyright by declaration. A public
domain notice is ambiguous at best and void at worst, and anyone wanting
to build on this seriously would have their lawyer stop them.
