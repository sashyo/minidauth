# Third-party code

minidauth redistributes no third-party code. This file records what it links against and why, so
the answer to "what is in the box" stays checkable rather than remembered.

## Linked, not redistributed

### MidgardJava

- A Maven dependency (`org.tide:MidgardJava`), not vendored into this repository.
- Copyright Tide Foundation Ltd.
- Wraps `libMidgardCore.so`. Required at runtime; obtained separately.

### Runtime dependencies

Declared in `pom.xml` and resolved by Maven: Jackson, JNA, Byte Buddy, Micrometer. Each carries its
own license, typically Apache-2.0. None is vendored here.

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
