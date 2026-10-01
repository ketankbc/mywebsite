-- Run this once in Supabase SQL Editor.
-- It removes direct anonymous writes and allows writes only through a password-checked RPC.

alter table public.clipboard enable row level security;

-- Keep public read access.
drop policy if exists "Anyone can read clipboard" on public.clipboard;
create policy "Anyone can read clipboard"
on public.clipboard
for select
to anon
using (id = 1);

-- IMPORTANT: remove any old public UPDATE/INSERT policies so the password cannot be bypassed.
drop policy if exists "Anyone can update clipboard" on public.clipboard;
drop policy if exists "Public can update clipboard" on public.clipboard;
drop policy if exists "Public can insert clipboard" on public.clipboard;
drop policy if exists "Anyone can insert clipboard" on public.clipboard;

create or replace function public.set_clipboard(p_content text, p_password_hash text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_password_hash <> 'f2512ad315b2f4176ed3daac94b1edeab0e253eefc534a1f27a964da64652cf5' then
    raise exception 'Invalid password';
  end if;

  update public.clipboard
     set content = coalesce(p_content, ''),
         updated_at = now()
   where id = 1;
end;
$$;

revoke all on function public.set_clipboard(text,text) from public;
grant execute on function public.set_clipboard(text,text) to anon;
