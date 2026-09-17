"""Generate the /integrations pages for the minidauth site.

Every fact on these pages comes from examples/<provider>/README.md in the repo.
"""
import html, json, os, sys

SITE = sys.argv[1]
BASE = "https://www.dauth.me"
REPO = "https://github.com/sashyo/minidauth"

P = [
    dict(
        slug="clerk", name="Clerk",
        chip=("Run end to end", True),
        status="Run end to end against a real Clerk application and the public Tide network: sign in, link, and a protected page that reads its answer from the grant record.",
        title="Clerk field-level encryption and roles · minidauth",
        desc="Keep Clerk for sign-in and add encryption, network signing and quorum-approved roles with minidauth. The key never sits on your server, and roles never go in a Clerk token.",
        lede="Clerk keeps the login, including its sign-in component. minidauth adds a key that no single server holds and roles that only a quorum of your admins can grant.",
        field="privateMetadata.tideVuid",
        field_why="Private metadata rather than public, because the browser should not be able to read or write the link.",
        rule="Clerk metadata can be copied into a session token, which makes it tempting to keep roles there. A role in a token your app can mint is a role your app can grant itself, so the example reads roles from minidauth on every request instead.",
        note_title="Clerk development instances",
        note="The Tide enclave returns to your app with a cross-site navigation, and on a Clerk development instance authenticateRequest can't identify the caller on that request (it answers dev-browser-missing). The example sets its own short-lived tide_link cookie, httpOnly and SameSite=Lax, when the link starts and reads it on the way back. It's a pattern worth keeping in production too.",
        run="""MINIDAUTH_OPS_TOKEN=<ops token> APP_URL=http://localhost:3003 \\
  node ../shared/register-callback.js

npm install
export CLERK_PUBLISHABLE_KEY=pk_test_...
export CLERK_SECRET_KEY=sk_test_...
export MINIDAUTH_TOKEN=dev-sample-app-token
npm start                                   # http://localhost:3003""",
        shot=("clerk-linked.png", 900, 260, "A Clerk user linked to a Tide identity, with granted roles listed", "A real Clerk user, linked to a Tide identity. The roles come from the quorum's grant record, not from Clerk."),
        extra=None,
    ),
    dict(
        slug="auth0", name="Auth0",
        chip=("Run end to end", True),
        status="Recorded against a real Auth0 tenant and the public Tide network.",
        title="Auth0 field-level encryption and roles · minidauth",
        desc="Keep Auth0 for sign-in and add encryption, network signing and quorum-approved roles with minidauth. The Auth0 token never carries a role, and the key never sits on your server.",
        lede="Auth0 keeps the login. minidauth adds a key that no single server holds and roles that only a quorum of your admins can grant. The Auth0 token never carries a role.",
        field="app_metadata.tide_vuid",
        field_why="App metadata rather than user metadata, because the user must not be able to edit the link.",
        rule="An Auth0 Action can copy app_metadata into a token. A role that arrives in a token your tenant can mint is a role your tenant can grant itself, so the example leaves roles out of Auth0 entirely and reads them from minidauth on every request.",
        note_title="Writing app_metadata",
        note="Saving the link needs the application authorised for the Management API with the update:users scope. In Auth0's API Access tab that lives under Client Access (machine to machine), not User-delegated Access, and it is the step most likely to be missed.",
        run="""# Auth0: a Regular Web Application, callback http://localhost:3002/callback,
# authorised for the Management API with update:users

MINIDAUTH_OPS_TOKEN=<ops token> APP_URL=http://localhost:3002 \\
  node ../shared/register-callback.js

npm install
export AUTH0_DOMAIN=your-tenant.au.auth0.com
export AUTH0_CLIENT_ID=...
export AUTH0_CLIENT_SECRET=...
export MINIDAUTH_TOKEN=dev-sample-app-token
npm start                                   # http://localhost:3002""",
        shot=None,
        extra=None,
    ),
    dict(
        slug="supabase", name="Supabase",
        chip=("Run end to end", True),
        status="Run end to end against a real Supabase project and the public Tide network, on the free tier with no card.",
        title="Supabase field-level encryption and roles · minidauth",
        desc="Keep Supabase Auth and Postgres, and add field-level encryption, network signing and quorum-approved roles with minidauth. Rows hold ciphertext and roles never live in the JWT.",
        lede="Supabase keeps the login and the database. minidauth adds a key that no single server holds, so sensitive columns hold ciphertext, and roles that only a quorum of your admins can grant.",
        field="app_metadata.tide_vuid",
        field_why="Written with the service role key. App metadata rather than user metadata, because a user can write their own user metadata.",
        rule="Supabase copies app_metadata straight into the access token, so it is tempting to put roles there and read them from the JWT. A role in a token your project can mint is a role your project can grant itself, so the example reads roles from the grant record on every request, and no row you edit in Supabase changes the answer.",
        note_title="Tokens issued before the link",
        note="Because the access token carries app_metadata, a token issued before the user linked their Tide identity won't contain the vuid. The example asks the user to sign in again rather than pretending the token refreshed. For the demo, turn email confirmations off under Authentication, Providers, Email.",
        run="""MINIDAUTH_OPS_TOKEN=<ops token> APP_URL=http://localhost:3004 \\
  node ../shared/register-callback.js

npm install
export SUPABASE_URL=https://xxxx.supabase.co
export SUPABASE_ANON_KEY=...
export SUPABASE_SERVICE_ROLE_KEY=...        # server side only
export MINIDAUTH_TOKEN=dev-sample-app-token
npm start                                   # http://localhost:3004""",
        shot=("supabase-granted.png", 900, 260, "A Supabase user linked to a Tide identity, with granted roles listed", "A real Supabase user, signed in again after linking. The roles are not in the Supabase token; they come from the grant record."),
        extra=("Two full apps on Supabase",
               'If you want more than a sign-in demo, two larger examples run on Supabase. <a href="%s/tree/main/examples/payouts">payouts</a> keeps bank details as ciphertext and only moves money the network has signed, so editing an amount in Supabase makes the row show as forged. <a href="%s/tree/main/examples/vault">vault</a> is a confidential client-records desk whose sensitive fields are sealed in the browser and revealed only for a granted role.' % (REPO, REPO)),
    ),
    dict(
        slug="cognito", name="Amazon Cognito",
        chip=("Setup scripted", False),
        status="npm run setup builds the whole Cognito side for you. The example shares its minidauth code with the others; it has not yet been run against a real user pool.",
        title="Amazon Cognito field-level encryption and roles · minidauth",
        desc="Keep Amazon Cognito for sign-in and add encryption, network signing and quorum-approved roles with minidauth. Roles stay out of Cognito tokens and the key never sits in your AWS account.",
        lede="Cognito keeps the login. minidauth adds a key that no single server holds and roles that only a quorum of your admins can grant. The Cognito token never carries a role.",
        field="custom:tide_vuid",
        field_why="A custom attribute on the user pool, written after the user links their Tide identity.",
        rule="A Pre Token Generation trigger can add group claims to a Cognito token, and it is the obvious place to put roles. A role that arrives in a token your AWS account can mint is a role your AWS account can grant itself. If you copy anything into the token, copy only the vuid, and let the example read roles from minidauth on every request.",
        note_title="What setup creates",
        note="A user pool with email sign-in and a tide_vuid attribute, an app client using the authorization code grant with openid and email, a hosted UI domain, and the callback registration with minidauth. It writes everything to .env and reuses it on the next run. npm run teardown removes the pool and domain again. The app's minidauth operator only needs the relying-party role, which can start and finish a sign-in and read grants, and nothing else.",
        run="""npm install
AWS_REGION=ap-southeast-2 MINIDAUTH_OPS_TOKEN=<ops token> npm run setup
npm start                                   # http://localhost:3001

npm run teardown                            # when you're finished""",
        shot=None,
        extra=None,
    ),
    dict(
        slug="better-auth", name="Better Auth",
        chip=("Runs locally", False),
        status="Runs locally and has been exercised against the live Tide network.",
        title="Better Auth field-level encryption and roles · minidauth",
        desc="Keep Better Auth for accounts, sessions and passwords, and add encryption, network signing and quorum-approved roles with minidauth, with one extra field on the user table.",
        lede="Better Auth keeps accounts, sessions and passwords, exactly as it would on its own. minidauth adds a key that no single server holds and roles that only a quorum of your admins can grant.",
        field="tideVuid on the user table, input: false",
        field_why="One extra field in auth.js, marked so the user can't set it. Everything else about authentication is untouched.",
        rule="The example's protected route reads roles from minidauth on every request, not from its own database, so editing app.db lets nobody in. Keep the Tide token in the session rather than the database.",
        note_title="A callback that can't be forged into a link",
        note="minidauth verifies the enclave's blind signature before it answers, so the vuid is proven rather than claimed. What the app still has to check is that a reply belongs to a sign-in it started, for the account that started it; the example does this with a short-lived map and refuses anything else.",
        run="""# minidauth running, with a vendor key and its policies deployed,
# this app's callback registered, and a relying-party operator in operators.json

npm install
npx @better-auth/cli migrate --yes
npm start                                   # http://localhost:3000""",
        shot=None,
        extra=None,
    ),
]

FONTS = '<link rel="preconnect" href="https://fonts.googleapis.com">\n<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Antonio:wght@400&family=Barlow:wght@400;500;600&family=IBM+Plex+Mono:wght@400&display=swap">'

FOOTER = '''    <footer>
      <div>
        MIT licensed. Built on the <a href="https://tide.org">Tide</a> network.
        <span class="disclaimer">Early software, not production ready. The
        <a href="https://github.com/sashyo/minidauth#honestly-what-is-proven">README</a> lists what
        has been run against the live network and what has not.</span>
      </div>
      <nav>
        <a href="{r}integrations/">Integrations</a>
        <a href="{r}projects/">Projects</a>
        <a href="{r}blog/">Blog</a>
        <a href="https://github.com/sashyo/minidauth">GitHub</a>
        <a href="https://github.com/sashyo/minidauth/blob/main/docs/running.md">Docs</a>
        <a href="https://discord.gg/XBMd9ny2q5">Discord</a>
      </nav>
    </footer>'''


def rail(r, current):
    items = [("Overview", r), ("Integrations", r + "integrations/"), ("Projects", r + "projects/")]
    out = []
    for label, href in items:
        cur = ' aria-current="page"' if label == current else ""
        out.append(f'    <a class="pill" href="{href}"{cur}>{label}</a>')
    out.append(f'    <a class="pill" href="{r}#start">Try it</a>')
    return (f'''  <nav class="rail" aria-label="Sections">
    <a class="brand" href="{r}" aria-label="minidauth, home"><img src="{r}assets/logo.svg" alt="minidauth" width="430" height="100"></a>
    <div class="knee" aria-hidden="true"></div>
''' + "\n".join(out) + f'''
    <div class="foot">
      <a class="pill" href="{r}blog/">Blog</a>
      <a class="pill" href="https://github.com/sashyo/minidauth">GitHub</a>
    </div>
  </nav>''')


def page(title, desc, canonical, r, current, ld, body):
    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(desc)}">
<link rel="canonical" href="{canonical}">
<meta property="og:type" content="article">
<meta property="og:site_name" content="minidauth">
<meta property="og:title" content="{html.escape(title)}">
<meta property="og:description" content="{html.escape(desc)}">
<meta property="og:url" content="{canonical}">
<meta property="og:image" content="{BASE}/assets/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="minidauth: give your existing login a key that nobody holds">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="{BASE}/assets/og.png">
<link rel="icon" href="{r}assets/mark.svg" type="image/svg+xml">
<link rel="icon" href="{r}favicon.ico" sizes="any">
<link rel="apple-touch-icon" href="{r}assets/apple-touch-icon.png">
{FONTS}
<link rel="stylesheet" href="{r}styles.css?v=20260917">
<script type="application/ld+json">
{json.dumps(ld, indent=2)}
</script>
</head>
<body>
<div class="shell">

{rail(r, current)}

  <main>
{body}
{FOOTER.format(r=r)}
  </main>
</div>

<script src="{r}site.js"></script>
</body>
</html>
'''


def chip(c):
    text, live = c
    return f'<span class="chip{" chip--live" if live else ""}">{text}</span>'


def provider_page(p):
    r = "../../"
    url = f"{BASE}/integrations/{p['slug']}/"
    others = " · ".join(
        f'<a href="../{o["slug"]}/">{o["name"]}</a>' for o in P if o["slug"] != p["slug"])
    shot = ""
    if p["shot"]:
        f, w, h, alt, cap = p["shot"]
        shot = f'''
      <figure class="shot">
        <img src="{r}assets/{f}" alt="{html.escape(alt)}" width="{w}" height="{h}" loading="lazy">
        <figcaption>{html.escape(cap)}</figcaption>
      </figure>'''
    extra = ""
    if p["extra"]:
        t, x = p["extra"]
        extra = f'''
    <section id="more">
      <h2>{t}</h2>
      <p>{x}</p>
    </section>
'''
    n = p["name"]
    body = f'''
    <header class="hero">
      <p class="label"><a href="../">Integrations</a> / {n}</p>
      <h1>{n} + minidauth <span>keep your login, add keys nobody holds</span></h1>
      <p class="lede">{p["lede"]}</p>
      <div class="hero-actions">
        <a class="btn btn--primary" href="{REPO}/tree/main/examples/{p["slug"]}">Open the {n} example</a>
        <a class="btn" href="{r}#start">Quick start</a>
      </div>
      <p class="micro">{chip(p["chip"])}</p>
    </header>

    <section id="split">
      <h2>What stays and what moves</h2>
      <dl class="rows">
        <div class="row">
          <dt>Stays with {n}</dt>
          <dd>Accounts, sessions, passwords and the sign-in screen. Nothing about how your users log in changes.</dd>
        </div>
        <div class="row">
          <dt>Moves to the network</dt>
          <dd>The key that encrypts and signs, which exists only as shares that 14 of 20 independent nodes have to cooperate to use, and the decision about who holds a role, which takes several of your admins approving it.</dd>
        </div>
      </dl>
    </section>

    <section id="steps">
      <h2>Adding it to a {n} app</h2>
      <ol class="steps">
        <li>
          <div>
            <h3>Store the link in <code>{html.escape(p["field"])}</code></h3>
            <p>{p["field_why"]}</p>
          </div>
        </li>
        <li>
          <div>
            <h3>Add one callback route</h3>
            <p>The user links their Tide identity in a page served by the Tide network, which neither your app nor minidauth can see into. The shared <code>link.js</code> drop-in adds the routes; you tell it who is signed in and where to store the vuid.</p>
          </div>
        </li>
        <li>
          <div>
            <h3>Read roles from minidauth, not from {n}</h3>
            <p>{p["rule"]}</p>
          </div>
        </li>
      </ol>{shot}
    </section>

    <section id="notes">
      <h2>{p["note_title"]}</h2>
      <p>{p["note"]}</p>
    </section>
{extra}
    <section id="tideless">
      <h2>Users without a Tide account</h2>
      <p>
        The {n} example also mounts a <code>/tideless</code> page. There, the signed-in {n} user
        encrypts and decrypts with no Tide account at all: their {n} user id is the subject, a
        role the quorum granted that id is the gate, and the browser never holds a credential. It
        needs a public, voucher-gated decrypt policy, which the
        <a href="{REPO}/blob/main/docs/running.md">setup guide</a> covers.
      </p>
    </section>

    <section id="run">
      <h2>Run the example</h2>
      <p>{p["status"]}</p>
      <div class="code">
        <button class="copy" type="button">Copy</button>
<pre>{html.escape(p["run"])}</pre>
      </div>
      <p style="margin-top:24px">
        minidauth itself has to be running first, with a vendor key created and its policies
        deployed. The <a href="{r}#start">quick start</a> is two Docker commands.
      </p>
      <p>
        Stuck on the {n} side? <a href="https://discord.gg/XBMd9ny2q5">Join the Discord</a> and
        I'll help you get it running.
      </p>
      <p class="micro">Also works with: {others}</p>
    </section>
'''
    ld = {
        "@context": "https://schema.org",
        "@graph": [
            {"@type": "TechArticle", "headline": f"{n} field-level encryption and roles with minidauth",
             "description": p["desc"], "url": url,
             "about": [{"@type": "SoftwareApplication", "name": "minidauth"},
                       {"@type": "SoftwareApplication", "name": n}]},
            {"@type": "BreadcrumbList", "itemListElement": [
                {"@type": "ListItem", "position": 1, "name": "minidauth", "item": f"{BASE}/"},
                {"@type": "ListItem", "position": 2, "name": "Integrations", "item": f"{BASE}/integrations/"},
                {"@type": "ListItem", "position": 3, "name": n, "item": url}]},
        ],
    }
    return page(p["title"], p["desc"], url, r, "Integrations", ld, body)


def index_page():
    r = "../"
    url = f"{BASE}/integrations/"
    items = "\n".join(f'''        <a class="post-link" href="{p["slug"]}/">
          <time>{chip(p["chip"])}</time>
          <div>
            <h3>{p["name"]}</h3>
            <p>{p["lede"]}</p>
          </div>
        </a>''' for p in P)
    body = f'''
    <header class="hero">
      <h1>Works with the login <span>you already have</span></h1>
      <p class="lede">
        minidauth runs next to your identity provider. Your users keep signing in the way they do
        today, and the key that encrypts and signs, along with the decision about who holds a
        role, moves out of your servers.
      </p>
      <p>
        The minidauth half is the same file in every integration. Each one is three steps: store
        one field the user can't edit, add one callback route, and read roles from minidauth
        instead of from your own tables.
      </p>
    </header>

    <section id="providers">
      <h2>Integrations</h2>
      <div class="posts">
{items}
      </div>
      <p style="margin-top:28px">
        Not on this list? The same pattern works with anything that gives you a stable user id.
        If you can't add a column, key the mapping on the id you already have.
      </p>
    </section>
'''
    ld = {"@context": "https://schema.org", "@type": "CollectionPage",
          "name": "minidauth integrations", "url": url,
          "hasPart": [{"@type": "TechArticle", "name": p["name"],
                       "url": f"{BASE}/integrations/{p['slug']}/"} for p in P]}
    return page("minidauth integrations: Clerk, Auth0, Supabase, Cognito, Better Auth",
                "Add threshold encryption, network signing and quorum-approved roles to Clerk, Auth0, Supabase, Amazon Cognito or Better Auth without replacing your login.",
                url, r, "Integrations", ld, body)



# Every fact below comes from the minidauth commits on each fork.
PROJ = [
    dict(
        slug="formbricks", name="Formbricks", kind="the open source survey platform",
        upstream="formbricks/formbricks", fork="sashyo/formbricks",
        run_url="https://github.com/sashyo/formbricks/tree/main/integrations/minidauth",
        title="Encrypted survey responses for Formbricks · minidauth",
        desc="A Formbricks fork where survey answers and contact attributes are sealed before they reach Postgres, and only a quorum-granted role can read them. How it is wired, and how to run it.",
        tagline="survey answers only a granted role can read",
        lede="Formbricks collects survey answers, and those answers are often the most sensitive thing a company holds about its customers. In this fork, answers are sealed before they reach Postgres, and reading them takes a role that a quorum of admins granted.",
        sealed=[("Survey answers", "The response data itself, which is every answer a respondent gave."),
                ("Contact attributes", "The per-contact details Formbricks keeps alongside responses.")],
        wiring=[("Sealed on write", "A Prisma client extension seals on create, update, upsert and createMany, so every path that stores a response goes through one place."),
                ("Opened for a granted reader", "Reveals run in the browser with the reader's own session key. The server-side open endpoint is off by default, so the server never needs to see plaintext."),
                ("Gated by a quorum role", "Reading needs a response-reader role the quorum granted. Revoke it in minidauth and reads stop, with no change to Formbricks or its login.")],
        hardening=["A sealing sidecar does the work. It holds no key and no reading identity of its own, and only relays.",
                   "The sidecar proves itself to minidauth with a private-key assertion rather than a shared bearer token, so a copy of the operators file is worthless.",
                   "Every inbound value is sealed, including one that merely looks sealed already, so a forged envelope can't slip plaintext into the database.",
                   "Sealing is idempotent, and batched into a single network fan-out.",
                   "Signing out revokes the minidauth session too, and only the server can trigger that."],
        status="A proof of concept, off unless MINIDAUTH_SEAL_URL is set, so an unconfigured checkout behaves exactly like upstream Formbricks.",
    ),
    dict(
        slug="twenty", name="Twenty", kind="the open source CRM",
        upstream="twentyhq/twenty", fork="sashyo/twenty",
        run_url="https://github.com/sashyo/twenty",
        title="Field-level encryption for Twenty CRM · minidauth",
        desc="A Twenty CRM fork where contact details, notes and tasks are sealed before they reach Postgres and decrypted only in the browser, for users holding a quorum-granted role.",
        tagline="contact data the server never sees in the clear",
        lede="A CRM is a list of people and everything a team knows about them. In this fork, the personal fields in Twenty are sealed before they reach Postgres and decrypted in the browser, so the server and its database only ever hold ciphertext.",
        sealed=[("People", "Name, emails and phone numbers (including the additional ones), job title and city."),
                ("Links", "LinkedIn and X links, both their URLs and their labels."),
                ("Notes and tasks", "Note bodies, and task titles and bodies.")],
        wiring=[("Sealed at the shared ORM", "Hooks in Twenty's workspace repository seal on insert, update and save, and handle reads, so every object goes through the same choke point."),
                ("Decrypted in the browser", "An Apollo link decrypts sealed fields client-side, using a session-bound token and a proof of possession tied to each request."),
                ("Gated by a quorum role", "Reading needs a crm-reader role the quorum granted, and revoking it takes effect across the whole instance with no deploy.")],
        hardening=["The token that allows a reveal lives for 15 seconds and is bound to the browser's session key.",
                   "A reveal token is only minted while a live server-side session exists, so a CRM token captured before logout can't keep minting them.",
                   "Signing out revokes the minidauth session, and retries so the revocation doesn't fail silently.",
                   "The dev server refuses to serve key files and .env files."],
        status="A proof of concept, off unless MINIDAUTH_SEAL_URL is set, so an unconfigured checkout behaves exactly like upstream Twenty.",
    ),
    dict(
        slug="cal", name="Cal.diy", kind="Cal.com's open source scheduling platform",
        upstream="calcom/cal.diy", fork="sashyo/cal.diy",
        run_url="https://github.com/sashyo/cal.diy",
        title="Encrypted booking and attendee data for Cal.com · minidauth",
        desc="A Cal.diy (Cal.com) fork where attendee names and phone numbers and booking details are sealed before they reach Postgres, and open only for the signed-in user holding a quorum-granted role.",
        tagline="bookings that open only for the right person",
        lede="Every booking carries someone's name, phone number and the reason they're meeting. In this fork of Cal.com's scheduling platform, those fields are sealed before they reach Postgres, and each request can only open them as its own signed-in user.",
        sealed=[("Attendees", "Name and phone number."),
                ("Bookings", "Title and description.")],
        wiring=[("Sealed on write", "A Prisma client extension seals the chosen fields before they reach Postgres and handles them again on the way out."),
                ("Opened per user", "Each authenticated request runs as its signed-in user, so a sealed field opens only for that verified user."),
                ("Gated by a quorum role", "The field opens only if minidauth's quorum grant says that user holds the reading role.")],
        hardening=["The sealing sidecar holds no reading identity of its own. Opening is delegated per user.",
                   "With no reader in the request, a field simply stays sealed, so there's never an open decryption service to abuse.",
                   "Every inbound value is sealed, so plaintext never reaches a sealed column."],
        status="A proof of concept, off unless MINIDAUTH_SEAL_URL is set, so an unconfigured checkout behaves exactly like upstream Cal.diy.",
    ),
    dict(
        slug="documenso", name="Documenso", kind="the open source DocuSign alternative",
        upstream="documenso/documenso", fork="sashyo/documenso",
        run_url="https://github.com/sashyo/documenso",
        title="Encrypted and quorum-signed documents for Documenso · minidauth",
        desc="A Documenso fork where document titles, recipient names and signatures are sealed before they reach Postgres, open only for a signed-in user holding a quorum-granted role, and each completion is threshold-signed by the Tide ORK cohort.",
        tagline="documents sealed at rest, opened for the reader, signed by a quorum",
        lede="A signed document is a promise, and the database that holds it knows the parties, the terms and the signatures. In this fork of Documenso, the open source DocuSign alternative, those fields are sealed before they reach Postgres, open only for a signed-in user a quorum granted the role, and each completion is threshold-signed by the Tide network so no operator can forge it.",
        sealed=[("Documents", "Title."),
                ("Recipients", "Name."),
                ("Emails to signers", "Subject and message."),
                ("Signatures and fields", "The typed or drawn signature, and the text a signer entered.")],
        wiring=[("Sealed on write", "A Prisma client extension seals the chosen fields before they reach Postgres and opens them again on the way out."),
                ("Opened per user", "Each authenticated request runs as its signed-in user; a recipient opening a signing link opens the document on the owner's reading authority once their token is verified."),
                ("Gated by a quorum role", "A field opens only if minidauth's quorum grant says that user holds the reading role. Revoke it and the same view goes dark."),
                ("Signed by a quorum", "On completion the Tide ORK cohort threshold-signs a statement about who signed what and when. The signature verifies against the vendor key; edit the row and it stops verifying.")],
        hardening=["The sidecar holds no reading identity and no signing key of its own. Opening and signing are delegated per user and gated on a quorum-granted role.",
                   "With no reader in the request, a field simply stays sealed, so there's never an open decryption service to abuse. Signing is best-effort and never blocks a person from signing.",
                   "Every inbound value is sealed, so plaintext never reaches a sealed column. Every completed signature is verifiable against the vendor key, and tampering the stored row breaks it."],
        status="A proof of concept, off unless MINIDAUTH_SEAL_URL is set, so an unconfigured checkout behaves exactly like upstream Documenso.",
    ),
    dict(
        slug="medusa", name="Medusa", kind="the open source Shopify alternative",
        upstream="medusajs/medusa", fork="sashyo/medusa",
        run_url="https://github.com/sashyo/medusa",
        title="Encrypted customer data for Medusa · minidauth",
        desc="A Medusa fork where customer and address personal data is sealed before it reaches Postgres, and opens only for a staff member holding a quorum-granted role.",
        tagline="a store whose database can't be read",
        lede="A commerce database is the classic breach: it knows who your customers are, where they live and how to reach them. In this fork of Medusa, the open source Shopify alternative, that personal data is sealed before it reaches Postgres and opens again in-request only for a staff member a quorum granted the reading role.",
        sealed=[("Customers", "First and last name, phone, company."),
                ("Addresses", "Name, phone, company, and the street lines, on customer and order addresses alike.")],
        wiring=[("Sealed on write", "One hook on Medusa's MikroORM base repository seals the chosen fields on create and update, so every module that stores them inherits it, and ciphertext is what reaches Postgres."),
                ("Opened per user", "The same base repository opens the fields when it serialises a read, for the staff member the HTTP layer verified for that request."),
                ("Gated by a quorum role", "A field opens only if minidauth's quorum grant says that staff member holds the reading role. A staff member without it gets ciphertext, and revoking it makes the same query go dark.")],
        hardening=["The sidecar holds no reading identity of its own. Opening is delegated per staff member and gated on a quorum-granted role.",
                   "With no reader in the request, a field simply stays sealed, so there's never an open decryption service to abuse.",
                   "Every inbound value is sealed, so plaintext never reaches a sealed column."],
        status="A proof of concept, off unless MINIDAUTH_SEAL_URL is set, so an unconfigured checkout behaves exactly like upstream Medusa.",
    ),
    dict(
        slug="rocketchat", name="Rocket.Chat", kind="the open source Slack alternative",
        upstream="RocketChat/Rocket.Chat", fork="sashyo/Rocket.Chat",
        run_url="https://github.com/sashyo/Rocket.Chat/tree/develop",
        title="Sealed chat messages for Rocket.Chat · minidauth",
        desc="A Rocket.Chat fork where the text of every message is sealed before it reaches MongoDB, and opens only for a member holding a quorum-granted role, over history and in real time.",
        tagline="a chat server whose messages the database can't read",
        lede="A chat server's most sensitive data is the message itself. In this fork of Rocket.Chat, the open source Slack alternative, a message's text is sealed before it reaches MongoDB, and opens back to plaintext only for a member a quorum granted the reading role, both when loading history and as messages arrive live.",
        sealed=[("Messages", "The body of every message. The room id, the sender and the timestamp stay in the clear, because a chat server sorts and routes on them.")],
        wiring=[("Sealed at the model layer", "One hook on Rocket.Chat's MongoDB base repository seals the message body on insert and update, so every write goes through the same place, and ciphertext is what reaches MongoDB."),
                ("Opened per reader, in history and live", "Loading a room opens the body as the requesting member through the common message normaliser. A message that arrives live opens per recipient, by reusing Rocket.Chat's own per-subscription transform in the streamer."),
                ("Gated by a quorum role", "A message opens only if minidauth's quorum grant says that member holds the reading role. A member without it sees ciphertext in the very same room, and revoking it makes reads go dark.")],
        hardening=["The sidecar holds no reading identity of its own. Opening is delegated per member and gated on a quorum-granted role.",
                   "With no reader in context, a message stays sealed, so there's never an open decryption service to abuse.",
                   "Rocket.Chat pre-parses each message into a rendered copy; that copy is dropped on write, so plaintext can't leak through it."],
        status="A proof of concept, off unless MINIDAUTH_SEAL_URL is set, so an unconfigured checkout behaves exactly like upstream Rocket.Chat.",
    ),
    dict(
        slug="chatwoot", name="Chatwoot", kind="the open source Zendesk alternative",
        upstream="chatwoot/chatwoot", fork="sashyo/chatwoot",
        run_url="https://github.com/sashyo/chatwoot/tree/minidauth-sealing",
        title="Sealed contacts and conversations for Chatwoot · minidauth",
        desc="A Chatwoot fork where a contact's name and phone and the body of every support message are sealed before they reach Postgres, and open only for an agent holding a quorum-granted role.",
        tagline="support conversations only a granted agent can read",
        lede="A support tool holds who your customers are and everything they told your team. In this fork of Chatwoot, the open source Zendesk alternative, a contact's name and phone and the body of every message are sealed before they reach Postgres, and open only for an agent a quorum granted the reading role. It is the first non-Node integration, proving the sealing sidecar is language-agnostic.",
        sealed=[("Contacts", "Name and phone number. Email and identifier stay in the clear, as the lookup keys Chatwoot dedupes and routes contacts on."),
                ("Messages", "The body of every message in a conversation.")],
        wiring=[("Sealed on write", "A small ActiveRecord concern seals the chosen fields in a before_save, so every write of a contact or a message goes through one place, and ciphertext is what reaches Postgres."),
                ("Opened per agent", "An after_find opens the fields as the signed-in agent Chatwoot already tracks for each request, so a sealed field opens only for that verified agent."),
                ("Gated by a quorum role", "A field opens only if minidauth's quorum grant says that agent holds the reading role. An agent without it sees ciphertext, and revoking it makes the same read go dark.")],
        hardening=["The sidecar holds no reading identity of its own. Opening is delegated per agent and gated on a quorum-granted role.",
                   "With no agent in context, a field stays sealed, so there's never an open decryption service to abuse.",
                   "The Ruby side signs its short-lived reader token with a private key rather than a shared secret, so a copy of a config file is worthless.",
                   "The tool's derived, pre-rendered copy of a message is dropped on write, so it can't shadow the sealed value."],
        status="A proof of concept, off unless MINIDAUTH_SEAL_URL is set, so an unconfigured checkout behaves exactly like upstream Chatwoot.",
    ),
    dict(
        slug="firefly", name="Firefly III", kind="the open source personal finance manager",
        upstream="firefly-iii/firefly-iii", fork="sashyo/firefly-iii",
        run_url="https://github.com/sashyo/firefly-iii/tree/minidauth-sealing",
        title="Sealed accounts and transactions for Firefly III · minidauth",
        desc="A Firefly III fork where payee names, IBANs, transaction descriptions and notes are sealed before they reach the database, and open only for a user holding a quorum-granted role, while balances stay in the clear so reports still work.",
        tagline="a budget file that reveals nothing if it is stolen",
        lede="A personal finance manager knows who you pay, how to reach them and what every transaction was for. In this fork of Firefly III, those fields are sealed before they reach the database, and open only for a user a quorum granted the reading role. The numbers a budgeting app has to add up stay in the clear, so reports and charts are untouched. It is a second non-Node integration, in PHP and Laravel, further proving the sealing sidecar is language-agnostic.",
        sealed=[("Accounts", "Payee and account names, and IBANs. The numeric balance stays in the clear so totals still add up."),
                ("Transactions", "The description of each transaction journal."),
                ("Notes", "The free-text note attached to an account or a transaction.")],
        wiring=[("Sealed on write", "An Eloquent trait seals the declared fields in the model's saving() event, so every write of an account, transaction or note goes through one place, and ciphertext is what reaches the database."),
                ("Opened per user", "The same trait's retrieved() event opens the fields as the signed-in user Laravel already tracks, then resyncs the attribute so an opened value is never written back as plaintext."),
                ("Gated by a quorum role", "A field opens only if minidauth's quorum grant says that user holds the reading role. Revoke it and the user sees their own account name as ciphertext, with no change to Firefly III or its login.")],
        hardening=["The sidecar holds no reading identity of its own. Opening is delegated per user and gated on a quorum-granted role.",
                   "With no reader in the request, a field simply stays sealed, so a read fails safe to ciphertext and never leaks plaintext by accident.",
                   "The PHP side signs its short-lived reader token with a private Ed25519 key rather than a shared secret, so a copy of a config file is worthless.",
                   "Numeric amounts and balances are never sealed, so budgets, reports and charts keep working exactly as upstream."],
        status="A proof of concept, off unless MINIDAUTH_SEAL_URL is set, so an unconfigured checkout behaves exactly like upstream Firefly III.",
    ),
    dict(
        slug="paperless", name="Paperless-ngx", kind="the open source document archive",
        upstream="paperless-ngx/paperless-ngx", fork="sashyo/paperless-ngx",
        run_url="https://github.com/sashyo/paperless-ngx/tree/minidauth-sealing",
        title="Sealed documents and OCR text for Paperless-ngx · minidauth",
        desc="A Paperless-ngx fork where a document's title, its OCR text, the correspondent and its notes are sealed before they reach the database and the search index, and open only for a user holding a quorum-granted role.",
        tagline="a document archive that reveals nothing if it is stolen",
        lede="A document archive is a pile of exactly the things a breach is about: who wrote to you, what the letter said, the notes you took. In this fork of Paperless-ngx, a document's title, its full OCR text, the correspondent and the notes are sealed before they reach the database, and open only for a user a quorum granted the reading role. It is a first integration in Python and Django, further proving the sealing sidecar is language-agnostic.",
        sealed=[("Documents", "Title and the full OCR text. The content length a statistics view needs stays a plain number."),
                ("Correspondents", "The name of who a document is from."),
                ("Notes", "The free-text notes attached to a document.")],
        wiring=[("Sealed on write", "A pre_save receiver seals the chosen fields on every create and update, so ciphertext is what reaches the database and, through it, the full-text index."),
                ("Opened per user, only in the response", "The DRF serializers open the sealed fields for the request's authenticated user. Opening never happens at the model or index layer, so plaintext exists only in the API response and never touches the search index on disk."),
                ("Gated by a quorum role", "A field opens only if minidauth's quorum grant says that user holds the reading role. Even a Paperless admin who can open the document sees ciphertext without it, and revoking it makes the same view go dark.")],
        hardening=["The sidecar holds no reading identity of its own. Opening is delegated per user and gated on a quorum-granted role.",
                   "With no granted reader in the request, a field stays sealed, so a read fails safe to ciphertext and never leaks plaintext by accident.",
                   "The full-text search index holds only ciphertext, because sealing is written before the index is built and opening happens only on the way out.",
                   "The reader token is a short-lived Ed25519 assertion signed with a private key, so a copy of a config file is worthless."],
        status="A proof of concept, off unless MINIDAUTH_SEAL_URL is set, so an unconfigured checkout behaves exactly like upstream Paperless-ngx.",
    ),
]


def rows(items):
    return "\n".join(f"""        <div class="row">
          <dt>{html.escape(a)}</dt>
          <dd>{html.escape(b)}</dd>
        </div>""" for a, b in items)


def project_page(q):
    r = "../../"
    url = f"{BASE}/projects/{q['slug']}/"
    others = " · ".join(f'<a href="../{o["slug"]}/">{o["name"]}</a>' for o in PROJ if o["slug"] != q["slug"])
    steps = "\n".join(f"""        <li>
          <div>
            <h3>{html.escape(a)}</h3>
            <p>{html.escape(b)}</p>
          </div>
        </li>""" for a, b in q["wiring"])
    hard = "\n".join(f"        <li>{html.escape(h)}</li>" for h in q["hardening"])
    n = q["name"]
    body = f"""
    <header class="hero">
      <p class="label"><a href="../">Projects</a> / {n}</p>
      <h1>{n} + minidauth <span>{q["tagline"]}</span></h1>
      <p class="lede">{q["lede"]}</p>
      <div class="hero-actions">
        <a class="btn btn--primary" href="https://github.com/{q["fork"]}">Open the fork</a>
        <a class="btn" href="https://github.com/{q["upstream"]}">Upstream {n}</a>
      </div>
      <p class="micro"><span class="chip chip--live">Run end to end</span></p>
    </header>

    <section id="sealed">
      <h2>What gets sealed</h2>
      <p>{n} is {q["kind"]}. These fields are stored as ciphertext, and nothing on the server can decrypt them.</p>
      <dl class="rows">
{rows(q["sealed"])}
      </dl>
    </section>

    <section id="wiring">
      <h2>How it's wired</h2>
      <ol class="steps">
{steps}
      </ol>
      <p style="margin-top:24px">
        The key that seals these fields exists only as shares across the Tide network, and 14 of 20
        nodes have to cooperate to use it. It is never on the {n} server.
      </p>
    </section>

    <section id="hardening">
      <h2>Details that matter</h2>
      <ul class="prose">
{hard}
      </ul>
    </section>

    <section id="status">
      <h2>Status and running it</h2>
      <p>{q["status"]} The fork's <a href="{q["run_url"]}">README</a> covers setup against a running minidauth.</p>
      <p>
        Want to do the same for another app, or stuck running this one?
        <a href="https://discord.gg/XBMd9ny2q5">Join the Discord</a> and I'll help you out.
      </p>
      <p class="micro">Other projects: {others} · <a href="{r}integrations/">Integrations</a></p>
    </section>
"""
    ld = {"@context": "https://schema.org", "@graph": [
        {"@type": "TechArticle", "headline": q["title"].split(" · ")[0], "description": q["desc"], "url": url,
         "about": [{"@type": "SoftwareApplication", "name": "minidauth"},
                   {"@type": "SoftwareSourceCode", "name": n, "codeRepository": f"https://github.com/{q['fork']}"}]},
        {"@type": "BreadcrumbList", "itemListElement": [
            {"@type": "ListItem", "position": 1, "name": "minidauth", "item": f"{BASE}/"},
            {"@type": "ListItem", "position": 2, "name": "Projects", "item": f"{BASE}/projects/"},
            {"@type": "ListItem", "position": 3, "name": n, "item": url}]}]}
    return page(q["title"], q["desc"], url, r, "Projects", ld, body)


def projects_index():
    r = "../"
    url = f"{BASE}/projects/"
    items = "\n".join(f"""        <a class="post-link" href="{q["slug"]}/">
          <time><span class="chip chip--live">Run end to end</span></time>
          <div>
            <h3>{q["name"]}</h3>
            <p>{q["lede"]}</p>
          </div>
        </a>""" for q in PROJ)
    body = f"""
    <header class="hero">
      <h1>Open source apps <span>with minidauth added</span></h1>
      <p class="lede">
        Real projects with their own logins and their own databases. Each fork seals the sensitive
        fields before they reach Postgres, and reading them takes a role a quorum granted.
      </p>
      <p>Each one is off unless it's configured, so an unconfigured checkout behaves exactly like upstream.</p>
    </header>

    <section id="list">
      <h2>Projects</h2>
      <div class="posts">
{items}
      </div>
      <p style="margin-top:28px">
        Adding it to something else? <a href="https://discord.gg/XBMd9ny2q5">Join the Discord</a> and
        I'll help you out.
      </p>
    </section>
"""
    ld = {"@context": "https://schema.org", "@type": "CollectionPage", "name": "Projects using minidauth", "url": url,
          "hasPart": [{"@type": "TechArticle", "name": q["name"], "url": f"{BASE}/projects/{q['slug']}/"} for q in PROJ]}
    names = ", ".join(q["name"] for q in PROJ)
    names_desc = ", ".join(q["name"] for q in PROJ[:-1]) + " and " + PROJ[-1]["name"]
    return page(f"Open source apps using minidauth: {names}",
                f"Forks of {names_desc} where sensitive fields are sealed before they reach the database and only a quorum-granted role can read them.",
                url, r, "Projects", ld, body)


os.makedirs(f"{SITE}/projects", exist_ok=True)
open(f"{SITE}/projects/index.html", "w").write(projects_index())
for q in PROJ:
    os.makedirs(f"{SITE}/projects/{q['slug']}", exist_ok=True)
    open(f"{SITE}/projects/{q['slug']}/index.html", "w").write(project_page(q))

os.makedirs(f"{SITE}/integrations", exist_ok=True)
open(f"{SITE}/integrations/index.html", "w").write(index_page())
for p in P:
    os.makedirs(f"{SITE}/integrations/{p['slug']}", exist_ok=True)
    open(f"{SITE}/integrations/{p['slug']}/index.html", "w").write(provider_page(p))

pages = ["/", "/integrations/"] + [f"/integrations/{p['slug']}/" for p in P] + \
    ["/projects/"] + [f"/projects/{q['slug']}/" for q in PROJ] + [
    "/blog/", "/blog/keep-roles-out-of-the-token", "/blog/prisma-field-level-encryption",
    "/blog/no-central-authority", "/blog/the-first-policy-is-the-only-one",
    "/blog/what-a-stolen-database-looks-like"]
sm = ['<?xml version="1.0" encoding="UTF-8"?>',
      '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
import datetime
today = datetime.date.today().isoformat()
sm += [f"  <url><loc>{BASE}{u}</loc><lastmod>{today}</lastmod></url>" for u in pages]
sm.append("</urlset>")
open(f"{SITE}/sitemap.xml", "w").write("\n".join(sm) + "\n")
open(f"{SITE}/robots.txt", "w").write(f"User-agent: *\nAllow: /\n\nSitemap: {BASE}/sitemap.xml\n")
print("generated", len(P) + len(PROJ) + 2, "pages, sitemap with", len(pages), "urls")
