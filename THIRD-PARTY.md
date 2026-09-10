# Third-party code

This repository contains no third-party code. The published container image does contain some, and
this file records what and why, so the answer to "what is in the box" stays checkable rather than
remembered.

## MidgardJava

- Copyright Tide Foundation Ltd. Wraps `libMidgardCore.so`, linux-x86-64 only.
- **In the repository:** never. Not the jar, not the source. Building from source needs the jar in
  `vendor/`, which git ignores; get it from Tide.
- **In the image:** the compiled jar, unmodified, shipped with Tide's permission. Midgard's source
  is private and is not included.

## Runtime dependencies

Declared in `pom.xml` and resolved by Maven: Jackson, JNA, Byte Buddy, Micrometer. Each carries its
own license, typically Apache-2.0. None is vendored here; the image carries their jars as released.

## The tunnel image

Alpine plus Cloudflare's `cloudflared` binary, downloaded from its GitHub releases at build time
and unmodified. Apache-2.0.

## Not included

**tide-js is not bundled.** An earlier build vendored a minified slice of it into the WordPress
consumer plugin, which was wrong twice over: it put someone else's code in this tree, and the
minifier stripped the copyright notice on the way through. Both are gone. Consumers that need
browser-side Tide cryptography obtain tide-js themselves.

## The Tide network

minidauth talks to the Tide ORK network. That is a service dependency, not a code one, and puts no
licensing obligation on this repository.

The vendor key lifecycle separately requires a Tide *licence* (the subscription the service
provisions through Stripe). That is a commercial arrangement between the operator and the Tide
Foundation and has nothing to do with the software license above. The two senses of "licence" are
easy to conflate in this project, so they are kept apart deliberately.
