# minidauth with Clerk

Clerk owns the login, including the sign-in component. minidauth supplies an identity the Tide
network vouches for and roles a quorum decides.

## What it looks like

Recorded against a real Clerk application and the public Tide network.

**1. Clerk's own sign-in.** Mounted straight from Clerk, so nothing about authentication changes.

![Clerk sign-in](docs/1-signin.png)

**2. Signed in, no Tide identity yet.** Authentication has happened. There is nothing to authorise
against, and the protected page turns you away.

![Signed in, not linked](docs/2-unlinked.png)

**3. Linked, and carrying roles.** The password for the Tide identity was typed into a page served by
the ORK network, which neither this app nor minidauth can see. The roles came from the grant record,
not from anything in Clerk.

![Linked with roles](docs/3-linked.png)

**4. The protected page.** Allowed, because the grant record says so.

![Allowed](docs/4-allowed.png)

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

## One thing Clerk needs that the others do not

The enclave returns by a cross site navigation, and on a Clerk **development** instance
`authenticateRequest` cannot identify the caller on one: the dev browser token is not carried, and it
answers `dev-browser-missing`. Asking the login provider who is returning is the fragile part of any
of these integrations, so this example does not. It sets its own short lived `tide_link` cookie when
the link starts and reads that on the way back.

That is worth copying even where the provider would have coped. The cookie is the app's own,
`httpOnly` and `SameSite=Lax`, so it survives exactly the navigation it needs to and nothing else.

## Status

Run end to end against a real Clerk application and the public Tide network: sign in, link, and a
protected page that reads its answer from the grant record. The screenshots above are that run.
