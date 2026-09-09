# Examples

Four auth systems, one integration. The point of having several is that the minidauth part does not
change: [`shared/minidauth.js`](shared/minidauth.js) is the same file in all of them.

| | | |
|---|---|---|
| [better-auth](better-auth) | :3000 | Runs locally, exercised against the live network |
| [cognito](cognito) | :3001 | `npm run setup` creates everything, unrun against a real pool |
| [auth0](auth0) | :3002 | Written from the API, unrun against a real tenant |
| [clerk](clerk) | :3003 | Written from the API, unrun against a real application |

## The pattern, in three steps

**1. Store one field.** The Tide identity, on your user record. Where it goes depends on what you
already run, and the only rule is that the user must not be able to edit it:

| | |
|---|---|
| Better Auth | a `tideVuid` column, `input: false` |
| Cognito | `custom:tide_vuid` |
| Auth0 | `app_metadata.tide_vuid` |
| Clerk | `privateMetadata.tideVuid` |

**2. Add one callback route.** Send the browser to `loginUrl(...)`, and when the enclave returns,
`completeLogin(...)` gives you a vuid minidauth has already verified. Your app still has to check
the reply belongs to a sign-in it started, for the account that started it. Every example does that
with a short-lived map and refuses anything else with a 400.

**3. Read authorisation, do not store it.** `rolesFor(vuid)` on every request. This is the step that
matters: it is what makes a role something your database cannot decide.

## The mistake all four are written to avoid

Every one of these systems will happily put custom claims in a token. Cognito has Pre Token
Generation triggers, Auth0 has Actions, Clerk has session token metadata, Better Auth has additional
fields.

Do not put roles there. **A role that arrives in a token your own system can mint is a role your own
system can grant itself**, and you are back to a single point of failure. The token carries identity;
the grant record carries authorisation, and only a quorum can change it.

## Encryption

None of these show it, because it happens in the browser inside the Tide enclave rather than in your
server. minidauth's own `/console/vault` does exactly that and is the shorter way to see it work.
