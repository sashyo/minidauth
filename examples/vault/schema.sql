-- Vault schema. In Supabase: SQL Editor → New query → paste → Run.
--
-- Row-level security is on with no policies, so only the server (secret key) touches these tables.
-- That is ordinary. What is not: every sensitive field is a ciphertext blob the network sealed, so
-- a dump of these tables — or a leaked service-role key — contains nothing readable.

create table if not exists public.vault_records (
  id uuid primary key default gen_random_uuid(),
  name text not null,                 -- clear, for the list
  ref  text,
  ciphertext jsonb not null default '{}',  -- { bank: "...", tax: "...", notes: "..." } — all sealed in the browser
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

-- Activity: one append-only feed for the audit trail and access requests. `type` is the event
-- ('seal' | 'reveal' | 'reveal_denied' | 'access_request'); `detail` is small context (never
-- plaintext). Written best-effort by the server, so the app keeps working before this table exists.
create table if not exists public.vault_activity (
  id uuid primary key default gen_random_uuid(),
  type text not null,
  actor uuid,                          -- the user id the event is about
  actor_email text,
  allowed boolean,
  detail jsonb not null default '{}',
  created_at timestamptz not null default now()
);
create index if not exists vault_activity_created_idx on public.vault_activity (created_at desc);

alter table public.vault_records  enable row level security;
alter table public.vault_activity enable row level security;
grant all on public.vault_records, public.vault_activity to service_role;
