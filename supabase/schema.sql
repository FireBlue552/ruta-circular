-- =====================================================================
-- Ruta Circular · Esquema de Supabase
-- Pégalo completo en: Supabase > SQL Editor > New query > Run
-- =====================================================================

-- 1) PERFILES (1 fila por usuario de Supabase Auth) --------------------
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  name        text not null check (char_length(name) between 1 and 80),
  avatar_url  text,
  created_at  timestamptz not null default now()
);

-- Crea el perfil automáticamente cuando alguien se registra
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, name, avatar_url)
  values (
    new.id,
    left(coalesce(new.raw_user_meta_data->>'full_name',
                  new.raw_user_meta_data->>'name',
                  split_part(new.email, '@', 1)), 80),
    new.raw_user_meta_data->>'avatar_url'
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 2) RECOLECCIONES -----------------------------------------------------
create table if not exists public.pickups (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null default auth.uid() references auth.users(id) on delete cascade,
  code       text not null unique default ('RC-' || upper(substr(replace(gen_random_uuid()::text,'-',''),1,8))),
  materials  text[] not null
             check (cardinality(materials) between 1 and 6
                    and materials <@ array['Cartón','Plástico','Vidrio','Metal','Papel','Otros']),
  kg         numeric(6,1) not null check (kg >= 1 and kg <= 200),
  fecha      date not null check (fecha >= current_date - 1),
  hora       text not null check (hora in ('08:00 - 10:00','10:00 - 12:00','12:00 - 14:00','14:00 - 16:00','16:00 - 18:00')),
  direccion  text not null check (char_length(direccion) between 5 and 200),
  status     text not null default 'Pendiente' check (status in ('Pendiente','Completada','Cancelada')),
  -- Puntos y CO2 los calcula la BASE DE DATOS: el usuario no puede inflarlos.
  pts        integer generated always as (round(kg * 25)::integer) stored,
  co2        numeric(8,2) generated always as (round(kg * 0.65, 2)) stored,
  created_at timestamptz not null default now()
);

create index if not exists pickups_user_idx on public.pickups (user_id, created_at desc);

-- 3) ROW-LEVEL SECURITY ------------------------------------------------
alter table public.profiles enable row level security;
alter table public.pickups  enable row level security;

-- profiles: cada usuario ve y edita SOLO su perfil
drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own" on public.profiles
  for select to authenticated using (id = auth.uid());

drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own" on public.profiles
  for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

-- pickups: cada usuario ve SOLO las suyas
drop policy if exists "pickups_select_own" on public.pickups;
create policy "pickups_select_own" on public.pickups
  for select to authenticated using (user_id = auth.uid());

-- pickups: solo puede crear las suyas y siempre como 'Pendiente'
drop policy if exists "pickups_insert_own" on public.pickups;
create policy "pickups_insert_own" on public.pickups
  for insert to authenticated
  with check (user_id = auth.uid() and status = 'Pendiente');

-- No hay policy de UPDATE ni DELETE para usuarios: no pueden cambiar el
-- estado ni borrar recolecciones. (Eso lo hará el equipo con service_role.)

-- Bloquea manipulación de campos: aunque llegue un INSERT raro,
-- las columnas sensibles se fuerzan desde el servidor.
revoke all on public.pickups  from anon;
revoke all on public.profiles from anon;

-- 4) RATE LIMITING: máx. 10 solicitudes por usuario por hora ------------
create or replace function public.limit_pickups()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  if (select count(*) from public.pickups
       where user_id = new.user_id
         and created_at > now() - interval '1 hour') >= 10 then
    raise exception 'Demasiadas solicitudes. Intenta de nuevo más tarde.'
      using errcode = 'P0001';
  end if;
  return new;
end;
$$;

drop trigger if exists pickups_rate_limit on public.pickups;
create trigger pickups_rate_limit
  before insert on public.pickups
  for each row execute function public.limit_pickups();

-- 5) ESTADÍSTICAS DE LA COMUNIDAD (solo totales, nunca datos personales) -
create or replace function public.community_stats()
returns table (points bigint, kg numeric, co2 numeric, users bigint)
language sql
stable
security definer set search_path = public
as $$
  select coalesce(sum(pts),0)::bigint,
         coalesce(sum(kg),0),
         coalesce(sum(co2),0),
         count(distinct user_id)::bigint
  from public.pickups
  where status <> 'Cancelada';
$$;

revoke all on function public.community_stats() from public;
grant execute on function public.community_stats() to anon, authenticated;
