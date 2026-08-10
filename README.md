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

Both are short enough to read in one sitting. They are public domain:
copy them, change them, redistribute them.

If what you are sending is serious, use these.

> **Note on language.** This README and `verify.py` are in English. The
> comments inside `sources/` are still in Spanish: those files must stay
> byte-for-byte identical to what the site serves, or the fingerprints
> stop matching. Translating them changes every hash, so it will be done
> as one deliberate pass rather than piecemeal.

## The protocol

Puzzle email (`@@`) splits every message into two pieces that do not
travel together: one goes by mail, the other stays stored. And the
message key travels masked with the digest of the **entire** ciphertext,
so you need every last byte of both pieces to recover it. Intercepting
one piece gets you nothing: it is not that you lack computing power, it
is that you lack data.

The specification is at <https://doubleat.email/?page=protocol>.

---

MIT licensed. See `LICENSE`.

Why not "public domain": Spanish law, where this is written, does not let
an author renounce copyright by declaration, so a public-domain notice is
ambiguous at best and void at worst. Anyone who wanted to build on this
seriously would have their lawyer stop them. MIT says the same thing —
take it, change it, sell it, no permission needed — and actually holds.
