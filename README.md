# Fingerprints of what doubleat.email serves you

This repository exists so that **you do not have to take our word for it**.

## The problem

[doubleat.email](https://doubleat.email) encrypts mail in your browser.
That is good, but it has a hole worth saying out loud: **the program that
does the encrypting is sent to you by our server**, every time you open
the page. A compromised server, or one under pressure from somebody,
could send you a version that keeps a copy of what you write, and you
would not notice.

This is true here and true of **any** encrypted mail that runs inside a
browser. Anyone selling you one without telling you this is hiding it
from you.

The site publishes the fingerprint of every file it serves. But that list
is served by the same server, so it **proves nothing**: whoever can change
the program can change the list too.

## What this repository is for

It lives somewhere else, owned by someone else, with its own history of
changes. Here you will find:

- `sources/` — the code exactly as it is served.
- `hashes.txt` — the SHA-256 fingerprint of each file.
- `verify.py` — downloads the files from the site and compares them.

```
python verify.py
```

If somebody tampered with what is served without also being able to
tamper with this repository, it would show.

## Checking by hand

Save the file from your browser and take its fingerprint:

```
sha256sum daeseal.js                      # Linux, Mac
certutil -hashfile daeseal.js SHA256      # Windows
```

Compare it with the one in `hashes.txt`.

## The limits, which we state too

**This does not prove the code is correct.** It proves that what is served
is what is published here. Whether the code does what it says can only be
learnt by reading it, and it is written to be read.

**If whoever controlled the server also controlled this repository, the
check would be worthless.** Look at the commit history: what is hard to
forge is not a file, it is a past.

**A mismatch is not always an attack.** By far the most likely cause is
that a new version was published and this repository is not up to date
yet. Check the date of the last commit before you worry.

## If you do not want to depend on the browser at all

Two programs run on your own computer and need none of our JavaScript:

- `sources/dae_open.py` — opens a puzzle email you have received.
- `sources/dae_send.py` — encrypts and sends one, with signature and
  attachments.

Both are short enough to read in one sitting. They are MIT licensed:
copy them, change them, redistribute them.

If what you are sending is serious, use these.

> **Note on language.** This README, `verify.py` and the documentation
> comments inside `sources/` are in English: they are read by exactly the
> people who do not trust us, and in Spanish they could not audit them.
> The messages the two tools *print while running* are still in Spanish,
> because today's users are. Translating those changes every hash, so it
> will be one deliberate pass rather than piecemeal.

## The protocol

Puzzle email (`@@`) splits every message into two pieces that do not
travel together: one goes by mail, the other stays stored. The message
key travels masked with the digest of the **entire** ciphertext, so the
key cannot be recovered from a partial message.

**Said precisely, because the sloppy version of this claim is false.**
We used to write that you need "every last byte" to recover anything.
That reads as though losing one byte protected you, and it does not: if
only a couple of bytes are missing you can simply try all the values,
and there are only 65,536 of them. Our own audit did exactly that and
got the whole message back in under a second.

What protects you is not the mask on its own — it is **how much** is
missing. The piece that travels by mail carries about a tenth of the
ciphertext; the other nine tenths never leave the store. Nobody guesses
nine tenths of a message. The mask is what turns that gap into
all-or-nothing instead of a partial leak: without the missing bytes you
do not get a worse copy of the message, you get nothing at all.

So intercepting one piece gets you nothing, and the honest reason is
worth stating plainly: it is not that you lack computing power, it is
that you lack most of the data.

**The wire specification is `SPEC.md`, in this repository.** It is
complete enough to write an implementation from without reading our code,
which is the only real test of whether a specification is any good. If
you have to open our source to find out what to do, that is a hole in the
document and we want to hear about it.

There is also a readable summary at
<https://doubleat.email/?page=implement>.

---

## Licences: two, and on purpose

**The code is MIT.** See `LICENSE`. That covers `sources/` and
`verify.py`.

**The specification is CC BY 4.0.** See the end of `SPEC.md`.

They are different things and they need different permissions. MIT is a
software licence — it speaks of "the Software", of copies and substantial
portions. Applied to a document, it leaves anyone wanting to quote a
paragraph in a standards draft, a paper, or a rival implementation's
manual asking their lawyer what it means. CC BY is the licence written
for documents and it is what everyone uses for standards. A specification
nobody can quote without hesitating is not a specification: it is the
documentation of one product.

Neither grants patent rights. MIT has no patent grant; if that ever
matters, Apache 2.0 does.

Why not "public domain", which is what this repository used to say:
Spanish law, where this is written, does not let an author renounce
copyright by declaration, so a public-domain notice is ambiguous at best
and void at worst. Anyone who wanted to build on this seriously would
have their lawyer stop them. MIT and CC BY say the same thing — take it,
change it, sell it, no permission needed — and actually hold.
