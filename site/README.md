# site

The public page for minidauth: what it is, where to use it, and `/blog`.

Static files, no build step, no dependencies. Everything is hand-written HTML with one stylesheet
and one small script.

```
site/
  index.html      the landing page
  styles.css      all of the styling for every page
  site.js         copy buttons, the cohort readout, rail highlighting
  assets/         logo and mark, copied from ../assets
  blog/
    index.html    the post list
    *.html        one file per post
```

## Preview it

```sh
python3 -m http.server 8777 --directory site
# http://127.0.0.1:8777/
```

## Deploy it

It is live at [dauth.me](https://dauth.me), on the Azure Static Web App `dauthme` in the `dauthme`
resource group (Tide Azure Sponsorship, Free tier, custom domain already resolved).

`staticwebapp.config.json` ships with the site and sets the 404, the cache headers and a content
security policy that allows only Google Fonts from outside the origin.

**Continuous, from GitHub.** `.github/workflows/site.yml` deploys `site/` on every push to `main`
that touches it. It needs the deployment token once, as a repository secret:

```sh
az staticwebapp secrets list -g dauthme -n dauthme --query "properties.apiKey" -o tsv \
  | gh secret set AZURE_STATIC_WEB_APPS_API_TOKEN --repo sashyo/minidauth
```

**One off, from this machine.** No commit needed, useful for checking a change on the real host:

```sh
TOKEN=$(az staticwebapp secrets list -g dauthme -n dauthme --query "properties.apiKey" -o tsv)
npx --yes @azure/static-web-apps-cli deploy ./site --deployment-token "$TOKEN" --env production
```

Leave off `--env production` to get a temporary preview URL instead of publishing to dauth.me.

## Adding a post

Copy an existing file in `blog/`, replace the article, and add an entry to the list in
`blog/index.html`. The newest post also gets an entry in the "Notes from building it" section of
`index.html`. Three files, no generator.

Keep the house style: plain sentences of varying length, real numbers and real error strings rather
than summaries of them, and the limits stated in the same breath as the claims.

## Design

One off-white ground, square blocks, and a red accent that only marks actions and refusals.
Nothing is outlined: edges are gradients of the ground itself, and only the things you press are
raised out of it. The block stack in the rail is the Star Trek part, kept small so the page stays
quiet.

Type is Antonio for headings, Barlow for text, IBM Plex Mono for anything the machine says. Teal is
for links and anything the network allowed. Everything else is grey.

The page is deliberately single-theme. It paints its own background and every colour explicitly, so
it does not inherit a host theme.

## Screenshots

`assets/vault-raw-store.png` and `assets/vault-records.png` are copies of
`examples/vault/docs/raw.png` and `examples/vault/docs/cohort.png`. Re-copy them if the vault
example's UI changes.
