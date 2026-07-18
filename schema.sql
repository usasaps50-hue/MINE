-- ===== デッキと慈悲(仮) Supabase スキーマ =====
-- Supabase ダッシュボード → SQL Editor に全部貼りつけて Run するだけ
-- BANのやり方: dm_accounts テーブルの banned 列を true にするだけ

create extension if not exists pgcrypto;

-- ---- アカウント ----
create table if not exists public.dm_accounts (
  id         uuid primary key default gen_random_uuid(),
  username   text unique not null,
  pass_hash  text not null,
  banned     boolean not null default false,
  save       text not null default '',
  created_at timestamptz not null default now(),
  last_login timestamptz
);

-- ---- セッション ----
create table if not exists public.dm_sessions (
  token      uuid primary key default gen_random_uuid(),
  account_id uuid not null references public.dm_accounts(id) on delete cascade,
  expires_at timestamptz not null
);

-- テーブルへの直接アクセスは全部禁止 (RPC関数経由のみ)
alter table public.dm_accounts enable row level security;
alter table public.dm_sessions enable row level security;
revoke all on public.dm_accounts from anon, authenticated;
revoke all on public.dm_sessions from anon, authenticated;

-- ---- ログイン ----
create or replace function public.dm_login(p_user text, p_pass text)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare
  v_acc dm_accounts%rowtype;
  v_token uuid;
begin
  p_user := trim(coalesce(p_user, ''));
  select * into v_acc from dm_accounts where username = p_user;
  if not found or v_acc.pass_hash <> crypt(coalesce(p_pass, ''), v_acc.pass_hash) then
    return jsonb_build_object('ok', false, 'msg', 'なまえか パスワードが ちがう');
  end if;
  if v_acc.banned then
    return jsonb_build_object('ok', false, 'msg', '⚠ このアカウントは ていしされています');
  end if;
  insert into dm_sessions (account_id, expires_at)
    values (v_acc.id, now() + interval '6 hours')
    returning token into v_token;
  update dm_accounts set last_login = now() where id = v_acc.id;
  return jsonb_build_object('ok', true, 'token', v_token, 'user', v_acc.username, 'save', v_acc.save);
end $$;

-- ---- 新規登録 ----
create or replace function public.dm_register(p_user text, p_pass text)
returns jsonb
language plpgsql security definer set search_path = public
as $$
begin
  p_user := trim(coalesce(p_user, ''));
  if p_user !~ '^[a-zA-Z0-9_ぁ-んァ-ヶ一-龠ー]{2,12}$' then
    return jsonb_build_object('ok', false, 'msg', 'なまえは 2〜12もじ (きごうは _ だけ)');
  end if;
  if length(coalesce(p_pass, '')) < 4 then
    return jsonb_build_object('ok', false, 'msg', 'パスワードは 4もじ いじょう');
  end if;
  begin
    insert into dm_accounts (username, pass_hash)
      values (p_user, crypt(p_pass, gen_salt('bf')));
  exception when unique_violation then
    return jsonb_build_object('ok', false, 'msg', 'そのなまえは もう つかわれている');
  end;
  return dm_login(p_user, p_pass);
end $$;

-- ---- 生存確認 (BAN/セッション切れチェック) ----
create or replace function public.dm_check(p_token uuid)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare
  v_banned boolean;
begin
  delete from dm_sessions where expires_at < now();
  select a.banned into v_banned
    from dm_sessions s join dm_accounts a on a.id = s.account_id
    where s.token = p_token;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'expired');
  end if;
  if v_banned then
    delete from dm_sessions where token = p_token;
    return jsonb_build_object('ok', false, 'reason', 'ban');
  end if;
  update dm_sessions set expires_at = now() + interval '6 hours' where token = p_token;
  return jsonb_build_object('ok', true);
end $$;

-- ---- セーブ ----
create or replace function public.dm_save(p_token uuid, p_save text)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare
  v_id uuid;
  v_banned boolean;
begin
  select a.id, a.banned into v_id, v_banned
    from dm_sessions s join dm_accounts a on a.id = s.account_id
    where s.token = p_token and s.expires_at >= now();
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'expired');
  end if;
  if v_banned then
    return jsonb_build_object('ok', false, 'reason', 'ban');
  end if;
  if length(coalesce(p_save, '')) > 20000 then
    return jsonb_build_object('ok', false, 'reason', 'toobig');
  end if;
  update dm_accounts set save = coalesce(p_save, '') where id = v_id;
  return jsonb_build_object('ok', true);
end $$;

-- ---- ログアウト ----
create or replace function public.dm_logout(p_token uuid)
returns jsonb
language plpgsql security definer set search_path = public
as $$
begin
  delete from dm_sessions where token = p_token;
  return jsonb_build_object('ok', true);
end $$;

grant execute on function public.dm_login(text, text)   to anon, authenticated;
grant execute on function public.dm_register(text, text) to anon, authenticated;
grant execute on function public.dm_check(uuid)          to anon, authenticated;
grant execute on function public.dm_save(uuid, text)     to anon, authenticated;
grant execute on function public.dm_logout(uuid)         to anon, authenticated;
