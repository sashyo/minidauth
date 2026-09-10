-- minidauth payouts. In Supabase: SQL Editor, New query, paste this, Run.
--
-- Row level security is on with no policies, so the publishable key reads nothing and only the
-- server touches these tables. That part is ordinary. What is not ordinary is what the secret key
-- gets somebody when it leaks, which is the point of the app.

create table if not exists public.payees (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  -- Encrypted in the Tide enclave before it left the browser. Nothing in Supabase can read it.
  bank_ciphertext text not null,
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.payouts (
  id uuid primary key default gen_random_uuid(),
  payee_id uuid not null references public.payees(id) on delete cascade,
  amount integer not null check (amount > 0),
  requested_by uuid not null references auth.users(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'signed', 'refused')),
  -- What the network was asked to sign, and what it answered.
  instruction text,
  signature text,
  refusal text,
  decided_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.payees enable row level security;
alter table public.payouts enable row level security;

grant all on public.payees, public.payouts to service_role;
