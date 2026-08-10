#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify.py - Compare what doubleat.email serves against this repository

Public domain. Standard library only.

------------------------------------------------------
WHAT THIS IS FOR
------------------------------------------------------
doubleat.email publishes, on its own site, the fingerprint of every file
it serves. That catches an accidental change, but it is worthless against
a compromised server: whoever can change the program can change the list
of fingerprints too. Comparing one thing against another from the same
place proves nothing.

This repository lives somewhere else, owned by someone else, with its own
history of changes. This program downloads the files from the site and
compares them with the ones here. If somebody tampered with what is
served without also being able to tamper with this repository, it would
show.

    python verify.py

------------------------------------------------------
WHAT THIS PROGRAM CANNOT TELL YOU
------------------------------------------------------
A clean run means what is served matches what is published here. It does
not mean the code is correct: that you only learn by reading it, and it
is written to be read.

And if whoever controlled the server also controlled this repository,
this check would be worthless. Look at the commit history: what is hard
to forge is not a file, it is a past.
"""

import hashlib
import secrets
import sys
import urllib.error
import urllib.request

SITE = "https://doubleat.email"

# Where each file lives on the site. The key is its name under sources/.
WHERE = {
    "daeseal.js":      "/assets/js/daeseal.js",
    "daecrypto.js":    "/assets/js/daecrypto.js",
    "daemime.js":      "/assets/js/daemime.js",
    "daemimebuild.js": "/assets/js/daemimebuild.js",
    "daecompose.js":   "/assets/js/daecompose.js",
    "selfread.js":     "/assets/js/selfread.js",
    "webmail.js":      "/assets/js/webmail.js",
    "dae_open.py":     "/assets/tools/dae_open.py",
    "dae_send.py":     "/assets/tools/dae_send.py",
}


def expected_hashes():
    expected = {}
    with open("hashes.txt", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest, _, name = line.partition(" ")
            expected[name.strip().lstrip("*")] = digest
    return expected


def fetch(path):
    # A DIFFERENT parameter on every run. With a fixed one, the cache in
    # front stores that address like any other and hands back a stale
    # copy: the check would report a mismatch where there is none, and a
    # warning that cries wolf is a warning people learn to ignore, which
    # is exactly what must not happen in this tool.
    url = "%s%s?c=%s" % (SITE, path, secrets.token_hex(8))
    request = urllib.request.Request(
        url, headers={"User-Agent": "verify.py (+doubleat.email)",
                      "Cache-Control": "no-cache"})
    with urllib.request.urlopen(request, timeout=60) as resp:
        return resp.read()


def main():
    try:
        expected = expected_hashes()
    except FileNotFoundError:
        sys.exit("hashes.txt not found. Run this inside the repository.")

    mismatched = 0
    unchecked = 0

    print("Comparing what %s serves against what is published here:\n" % SITE)

    for name, path in WHERE.items():
        if name not in expected:
            print("  ?  %-16s not listed in hashes.txt" % name)
            unchecked += 1
            continue

        try:
            data = fetch(path)
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            print("  ?  %-16s could not be downloaded (%s)" % (name, e))
            unchecked += 1
            continue

        actual = hashlib.sha256(data).hexdigest()
        if actual == expected[name]:
            print("  OK %-16s matches" % name)
        else:
            mismatched += 1
            print("  NO %-16s DOES NOT MATCH" % name)
            print("       here:   %s" % expected[name])
            print("       served: %s" % actual)

    print()
    if mismatched:
        print("%d file(s) DO NOT match." % mismatched)
        print()
        print("Before you worry: by far the most likely cause is that a new")
        print("version was published and this repository is not up to date")
        print("yet. Check the date of the last commit.")
        print()
        print("If the repository is current and it still does not match,")
        print("there is something to explain. Do not send anything sensitive")
        print("from the website until you know what happened: use dae_send.py")
        print("and dae_open.py, which run on your own computer.")
        sys.exit(1)

    if unchecked:
        print("Everything that could be checked matches, but %d file(s)"
              " could not be looked at." % unchecked)
        sys.exit(2)

    print("Everything matches what is published in this repository.")
    print()
    print("Mind what that means: the served code is the published code.")
    print("Not that the code is correct. That you only learn by reading it.")


if __name__ == "__main__":
    main()
