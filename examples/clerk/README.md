# minidauth with Clerk

Clerk owns the login, including the sign-in component. minidauth supplies an identity the Tide
network vouches for and roles a quorum decides.

## Run it

In Clerk, create an application and take both keys. Then register this app's Tide callback with
minidauth, which merges rather than replaces:

```sh
MINIDAUTH_OPS_TOKEN=<ops token> APP_URL=http://localhost:3003 \
  node ../shared/register-callback.js
```

```sh
npm install
export CLERK_PUBLISHABLE_KEY=pk_test_...
export CLERK_SECRET_KEY=sk_test_...
export MINIDAUTH_TOKEN=dev-sample-app-token
npm start                                   # http://localhost:3003
```

The sign-in is Clerk's own mounted component, so this example has no login form of its own. That is
the point: nothing about authentication changes.

## Where the link is stored, and why

`privateMetadata.tideVuid`, not `publicMetadata`, because the browser should not be able to read or
write it.

Roles stay out of Clerk. Metadata can be put into a session token, and a role in a token this app
can mint is a role this app can grant itself. `/protected` reads roles from minidauth on every
request instead.

## Status

Written from the Clerk API and not yet run against a real application. The minidauth half is shared
with [the Better Auth example](../better-auth), which is exercised against the live network.
