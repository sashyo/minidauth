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

alter table public.vault_records enable row level security;
grant all on public.vault_records to service_role;
