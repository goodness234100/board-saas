-- Run this once in your Supabase project's SQL editor.

-- Extends auth.users with app-specific fields (namely: has this person paid?)
create table if not exists public.profiles (
  id uuid references auth.users on delete cascade primary key,
  email text,
  paid boolean not null default false,
  created_at timestamptz not null default now()
);

-- Automatically create a profile row whenever someone signs up
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email) values (new.id, new.email);
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- One row per sticky note
create table if not exists public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users on delete cascade not null,
  x real not null default 40,
  y real not null default 40,
  text text not null default '',
  color text not null default '#ffe9a8',
  pinned boolean not null default false,
  image_path text,              -- storage path inside the note-images bucket, e.g. "<user_id>/<note_id>.jpg"
  updated_at timestamptz not null default now()
);

-- If you're adding images to a database that already has the notes table,
-- run this instead of recreating the table:
-- alter table public.notes add column if not exists image_path text;

-- One row per saved folder (a tagged, archived group of pinned notes)
create table if not exists public.folders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users on delete cascade not null,
  tag text not null,
  files jsonb not null default '[]',
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.notes enable row level security;
alter table public.folders enable row level security;

-- Each person can only ever see/edit their own rows
drop policy if exists "own profile read" on public.profiles;
create policy "own profile read" on public.profiles
  for select using (auth.uid() = id);

drop policy if exists "own notes" on public.notes;
create policy "own notes" on public.notes
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "own folders" on public.folders;
create policy "own folders" on public.folders
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- Note: profiles.paid is only ever updated by the Paystack webhook, which uses
-- the service role key and therefore bypasses RLS. Regular users cannot set
-- their own "paid" flag through the client.

-- ============================================================
-- IMAGE UPLOADS: a private storage bucket, one folder per user
-- ============================================================
-- Files are stored at "<user_id>/<filename>" inside this bucket.
-- The bucket is private — nobody can access a file's URL directly.
-- The app requests a short-lived signed URL each time it needs to
-- display an image, and only the owning user is allowed to do that.

insert into storage.buckets (id, name, public)
values ('note-images', 'note-images', false)
on conflict (id) do nothing;

drop policy if exists "users upload own note images" on storage.objects;
create policy "users upload own note images"
  on storage.objects for insert
  with check (
    bucket_id = 'note-images'
    and (storage.foldername(name))[1] = auth.uid()::text
  );

drop policy if exists "users read own note images" on storage.objects;
create policy "users read own note images"
  on storage.objects for select
  using (
    bucket_id = 'note-images'
    and (storage.foldername(name))[1] = auth.uid()::text
  );

drop policy if exists "users update own note images" on storage.objects;
create policy "users update own note images"
  on storage.objects for update
  using (
    bucket_id = 'note-images'
    and (storage.foldername(name))[1] = auth.uid()::text
  );

drop policy if exists "users delete own note images" on storage.objects;
create policy "users delete own note images"
  on storage.objects for delete
  using (
    bucket_id = 'note-images'
    and (storage.foldername(name))[1] = auth.uid()::text
  );
