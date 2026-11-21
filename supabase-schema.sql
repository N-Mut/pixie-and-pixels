-- Pixie & Pixels: execute once in Supabase SQL Editor.
-- Auth > Providers: email enabled. No public database policies for anonymous visitors.
create table if not exists public.memberships (
 owner_id uuid not null references auth.users(id) on delete cascade,
 user_id uuid not null references auth.users(id) on delete cascade,
 role text not null check (role in ('owner','supervisor')),
 primary key(owner_id,user_id)
);
create table if not exists public.workspace_state (
 owner_id uuid primary key references auth.users(id) on delete cascade,
 payload jsonb not null default '{}'::jsonb,
 updated_at timestamptz not null default now()
);
-- SECURITY DEFINER avoids recursive RLS when checking memberships.
create or replace function public.is_workspace_member(target_owner uuid)
returns boolean language sql security definer stable set search_path = '' as $$
 select exists (select 1 from public.memberships where owner_id=target_owner and user_id=(select auth.uid()) and role in ('owner','supervisor'));
$$;
revoke all on function public.is_workspace_member(uuid) from public;
grant execute on function public.is_workspace_member(uuid) to authenticated;
alter table public.memberships enable row level security;
alter table public.workspace_state enable row level security;
create policy "members can view own workspace memberships" on public.memberships for select to authenticated using (public.is_workspace_member(owner_id));
create policy "owner can add members" on public.memberships for insert to authenticated with check (owner_id=(select auth.uid()) and role in ('owner','supervisor'));
create policy "owner can remove members" on public.memberships for delete to authenticated using (owner_id=(select auth.uid()) and user_id<>(select auth.uid()));
create policy "members can view workspace" on public.workspace_state for select to authenticated using (public.is_workspace_member(owner_id));
create policy "members can create workspace" on public.workspace_state for insert to authenticated with check (public.is_workspace_member(owner_id));
-- Prevent a supervisor from changing completion, learner notes or any other owner-managed data.
-- Supervisors may edit ONLY lesson overrides, challenges and supervisor notes.
create or replace function public.restrict_supervisor_payload()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
 if (select auth.uid()) is distinct from new.owner_id then
   if (coalesce(new.payload,'{}'::jsonb) - 'overrides' - 'supervisorNotes' - 'challenges')
      is distinct from
      (coalesce(old.payload,'{}'::jsonb) - 'overrides' - 'supervisorNotes' - 'challenges') then
     raise exception 'Supervisors may only update lessons, challenges and supervisor notes';
   end if;
 end if;
 return new;
end; $$;
drop trigger if exists restrict_pixie_supervisor_updates on public.workspace_state;
create trigger restrict_pixie_supervisor_updates before update on public.workspace_state
for each row execute function public.restrict_supervisor_payload();
create policy "members can edit workspace" on public.workspace_state for update to authenticated using (public.is_workspace_member(owner_id)) with check (public.is_workspace_member(owner_id));
-- Register an owner membership automatically for each new account, no extra admin credentials needed.
create or replace function public.create_owner_membership()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
 insert into public.memberships(owner_id,user_id,role) values (new.id,new.id,'owner');
 return new;
end; $$;
drop trigger if exists on_auth_user_created_pixie on auth.users;
create trigger on_auth_user_created_pixie after insert on auth.users for each row execute function public.create_owner_membership();
-- IMPORTANT: to give brother supervisor permissions, first create/confirm BOTH email users.
-- Then the owner executes (or authorized admin executes) the statement below using REAL UUIDs:
-- insert into public.memberships(owner_id,user_id,role)
-- values ('LEARNER_AUTH_USER_UUID','BROTHER_AUTH_USER_UUID','supervisor');
-- The trigger above protects completed days and learner notes from supervisor edits.
-- This v1 uses one JSON document, so simultaneous saves from two devices can overwrite one another.
-- For a multi-user production system, separate progress/notes/overrides tables and add conflict handling.
