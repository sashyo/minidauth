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
        <a href="{r}blog/">Blog</a>
        <a href="https://github.com/sashyo/minidauth">GitHub</a>
        <a href="https://github.com/sashyo/minidauth/blob/main/docs/running.md">Docs</a>
      </nav>
    </footer>'''


def rail(r, current):
    items = [("Overview", r), ("Integrations", r + "integrations/")]
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
<link rel="icon" href="{r}assets/mark.svg" type="image/svg+xml">
{FONTS}
<link rel="stylesheet" href="{r}styles.css">
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


os.makedirs(f"{SITE}/integrations", exist_ok=True)
open(f"{SITE}/integrations/index.html", "w").write(index_page())
for p in P:
    os.makedirs(f"{SITE}/integrations/{p['slug']}", exist_ok=True)
    open(f"{SITE}/integrations/{p['slug']}/index.html", "w").write(provider_page(p))

pages = ["/", "/integrations/"] + [f"/integrations/{p['slug']}/" for p in P] + [
    "/blog/", "/blog/no-central-authority", "/blog/the-first-policy-is-the-only-one",
    "/blog/what-a-stolen-database-looks-like"]
sm = ['<?xml version="1.0" encoding="UTF-8"?>',
      '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
sm += [f"  <url><loc>{BASE}{u}</loc></url>" for u in pages]
sm.append("</urlset>")
open(f"{SITE}/sitemap.xml", "w").write("\n".join(sm) + "\n")
open(f"{SITE}/robots.txt", "w").write(f"User-agent: *\nAllow: /\n\nSitemap: {BASE}/sitemap.xml\n")
print("generated", len(P) + 1, "pages, sitemap with", len(pages), "urls")
