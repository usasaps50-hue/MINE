-- ===== デッキと慈悲(仮) Supabase スキーマ =====
-- Supabase ダッシュボード → SQL Editor に全部貼りつけて Run するだけ
-- BANのやり方: dm_accounts テーブルの banned 列を true にするだけ

create extension if not exists pgcrypto with schema extensions;

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
language plpgsql security definer set search_path = public, extensions
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
language plpgsql security definer set search_path = public, extensions
as $$
begin
  p_user := trim(coalesce(p_user, ''));
  if p_user !~ '^[a-zA-Z0-9_ぁ-んァ-ヶ一-龠ー]{2,12}$' then
    return jsonb_build_object('ok', false, 'msg', 'なまえは 2〜12もじ (きごうは _ だけ)');
  end if;
  if length(coalesce(p_pass, '')) < 4 then
    return jsonb_build_object('ok', false, 'msg', 'パスワードは 4もじ いじょう');
  end if;
  if p_user = 'システム' then
    return jsonb_build_object('ok', false, 'msg', 'そのなまえは つかえません');
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
language plpgsql security definer set search_path = public, extensions
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
language plpgsql security definer set search_path = public, extensions
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
language plpgsql security definer set search_path = public, extensions
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

-- ================================================
-- フレンド機能
-- ================================================
create table if not exists public.dm_friends (
  id uuid primary key default gen_random_uuid(),
  a_id uuid not null references public.dm_accounts(id) on delete cascade, -- 申請した側
  b_id uuid not null references public.dm_accounts(id) on delete cascade, -- 受けた側
  status text not null default 'pending',  -- pending / ok
  created_at timestamptz not null default now(),
  unique (a_id, b_id)
);
alter table public.dm_friends enable row level security;
revoke all on public.dm_friends from anon, authenticated;

-- トークン→アカウントID (内部用)
create or replace function public.dm_sess_(p_token uuid)
returns uuid
language sql security definer set search_path = public, extensions
as $$
  select s.account_id from dm_sessions s
  where s.token = p_token and s.expires_at >= now();
$$;

-- フレンド申請 (相手からの申請が来ていたら自動で承認)
create or replace function public.dm_friend_request(p_token uuid, p_name text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v_me uuid; v_tgt uuid;
begin
  v_me := dm_sess_(p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'msg', 'セッションぎれ。ログインしなおして'); end if;
  select id into v_tgt from dm_accounts where username = trim(coalesce(p_name, ''));
  if not found then return jsonb_build_object('ok', false, 'msg', 'そのなまえの ひとは いない…'); end if;
  if v_tgt = v_me then return jsonb_build_object('ok', false, 'msg', 'じぶんには おくれないよ!'); end if;
  if exists (select 1 from dm_friends where ((a_id = v_me and b_id = v_tgt) or (a_id = v_tgt and b_id = v_me)) and status = 'ok') then
    return jsonb_build_object('ok', false, 'msg', 'もう フレンドだよ!');
  end if;
  -- 相手からの申請が pending なら 承認あつかい
  if exists (select 1 from dm_friends where a_id = v_tgt and b_id = v_me and status = 'pending') then
    update dm_friends set status = 'ok' where a_id = v_tgt and b_id = v_me;
    return jsonb_build_object('ok', true, 'msg', 'あいても しんせいしてた! フレンドに なった!!');
  end if;
  if exists (select 1 from dm_friends where a_id = v_me and b_id = v_tgt) then
    return jsonb_build_object('ok', false, 'msg', 'もう しんせいずみ。へんじを まとう');
  end if;
  insert into dm_friends (a_id, b_id) values (v_me, v_tgt);
  return jsonb_build_object('ok', true, 'msg', p_name || ' に しんせいを おくった!');
end $$;

-- 申請へのへんじ
create or replace function public.dm_friend_respond(p_token uuid, p_name text, p_accept boolean)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v_me uuid; v_tgt uuid;
begin
  v_me := dm_sess_(p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'msg', 'セッションぎれ'); end if;
  select id into v_tgt from dm_accounts where username = trim(coalesce(p_name, ''));
  if not found then return jsonb_build_object('ok', false, 'msg', 'いない…'); end if;
  if p_accept then
    update dm_friends set status = 'ok' where a_id = v_tgt and b_id = v_me and status = 'pending';
  else
    delete from dm_friends where a_id = v_tgt and b_id = v_me and status = 'pending';
  end if;
  return jsonb_build_object('ok', true);
end $$;

-- フレンド一覧 (friends / incoming / outgoing)
create or replace function public.dm_friends(p_token uuid)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v_me uuid;
begin
  v_me := dm_sess_(p_token);
  if v_me is null then return jsonb_build_object('ok', false); end if;
  return jsonb_build_object(
    'ok', true,
    'friends', coalesce((
      select jsonb_agg(a.username order by a.username)
      from dm_friends f
      join dm_accounts a on a.id = case when f.a_id = v_me then f.b_id else f.a_id end
      where (f.a_id = v_me or f.b_id = v_me) and f.status = 'ok'
    ), '[]'::jsonb),
    'incoming', coalesce((
      select jsonb_agg(a.username order by a.username)
      from dm_friends f join dm_accounts a on a.id = f.a_id
      where f.b_id = v_me and f.status = 'pending'
    ), '[]'::jsonb),
    'outgoing', coalesce((
      select jsonb_agg(a.username order by a.username)
      from dm_friends f join dm_accounts a on a.id = f.b_id
      where f.a_id = v_me and f.status = 'pending'
    ), '[]'::jsonb)
  );
end $$;

-- フレンドの プロフィール(セーブ)を みる。フレンドどうしのみ
create or replace function public.dm_profile(p_token uuid, p_name text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v_me uuid; v_tgt uuid; v_save text;
begin
  v_me := dm_sess_(p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'msg', 'セッションぎれ'); end if;
  select id, save into v_tgt, v_save from dm_accounts where username = trim(coalesce(p_name, ''));
  if not found then return jsonb_build_object('ok', false, 'msg', 'いない…'); end if;
  if v_tgt <> v_me and not exists (
    select 1 from dm_friends
    where ((a_id = v_me and b_id = v_tgt) or (a_id = v_tgt and b_id = v_me)) and status = 'ok'
  ) then
    return jsonb_build_object('ok', false, 'msg', 'フレンドじゃ ないと みれない');
  end if;
  return jsonb_build_object('ok', true, 'save', coalesce(v_save, ''));
end $$;

-- 進行度ランキング (bestProg で じょうい30にん)
create or replace function public.dm_ranking()
returns jsonb
language sql security definer set search_path = public, extensions
as $$
  select coalesce(jsonb_agg(jsonb_build_object('name', name, 'prog', prog, 'lv', lv) order by prog desc, lv desc), '[]'::jsonb)
  from (
    select a.username as name,
           coalesce((nullif(a.save, '')::jsonb ->> 'bestProg')::int, 1) as prog,
           coalesce((nullif(a.save, '')::jsonb ->> 'lv')::int, 1) as lv
    from dm_accounts a
    where a.banned = false and a.username <> 'システム' and a.save like '%bestProg%'
    order by prog desc, lv desc
    limit 30
  ) t;
$$;

-- ================================================
-- システムからの プレゼント (お金 / 装備)
-- ================================================
create table if not exists public.dm_gifts (
  id         bigserial primary key,
  to_id      uuid not null references public.dm_accounts(id) on delete cascade,
  kind       text not null,               -- 'coins' / 'armor' / 'orb' / 'sale'
  amount     int  not null default 0,     -- coins/orb のかず、sale は うれた ねだん
  item       text,                        -- armor/orb のキー、sale は ぶきの なまえ
  claimed    boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists dm_gifts_to_idx on public.dm_gifts (to_id) where claimed = false;
alter table public.dm_gifts enable row level security;
revoke all on public.dm_gifts from anon, authenticated;

-- 管理者(システム)だけが おくれる
create or replace function public.dm_admin_gift(p_token uuid, p_name text, p_kind text, p_amount int, p_item text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v_me uuid; v_meName text; v_tgt uuid;
begin
  v_me := dm_sess_(p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'msg', 'セッションぎれ'); end if;
  select username into v_meName from dm_accounts where id = v_me;
  if v_meName is distinct from 'システム' then
    return jsonb_build_object('ok', false, 'msg', 'システムアカウント せんようです');
  end if;
  if p_kind not in ('coins', 'armor', 'orb') then
    return jsonb_build_object('ok', false, 'msg', 'おくれない しゅるい');
  end if;
  if p_kind = 'coins' and coalesce(p_amount, 0) <= 0 then
    return jsonb_build_object('ok', false, 'msg', 'きんがくを いれてね');
  end if;
  if p_kind in ('armor', 'orb') and coalesce(p_item, '') = '' then
    return jsonb_build_object('ok', false, 'msg', 'なにを おくるか えらんでね');
  end if;
  select id into v_tgt from dm_accounts where username = trim(coalesce(p_name, ''));
  if not found then return jsonb_build_object('ok', false, 'msg', 'そのなまえの ひとは いない'); end if;
  insert into dm_gifts (to_id, kind, amount, item)
    values (v_tgt, p_kind, coalesce(p_amount, 0), p_item);
  return jsonb_build_object('ok', true);
end $$;

-- じぶんあての プレゼントを うけとる (とると claimed になる)
create or replace function public.dm_gifts_claim(p_token uuid)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v_me uuid; v_out jsonb;
begin
  v_me := dm_sess_(p_token);
  if v_me is null then return '[]'::jsonb; end if;
  with got as (
    update dm_gifts set claimed = true
    where to_id = v_me and claimed = false
    returning kind, amount, item, id
  )
  select coalesce(jsonb_agg(jsonb_build_object('kind', kind, 'amount', amount, 'item', item) order by id), '[]'::jsonb)
    into v_out from got;
  return v_out;
end $$;

grant execute on function public.dm_friend_request(uuid, text)           to anon, authenticated;
grant execute on function public.dm_friend_respond(uuid, text, boolean)  to anon, authenticated;
grant execute on function public.dm_friends(uuid)                        to anon, authenticated;
grant execute on function public.dm_profile(uuid, text)                  to anon, authenticated;
grant execute on function public.dm_ranking()                            to anon, authenticated;
grant execute on function public.dm_admin_gift(uuid, text, text, int, text) to anon, authenticated;
grant execute on function public.dm_gifts_claim(uuid)                    to anon, authenticated;

-- ================================================
-- マーケット (プレイヤーどうしの ばいばい)
-- ================================================
create table if not exists public.dm_market (
  id          bigserial primary key,
  seller_id   uuid not null references public.dm_accounts(id) on delete cascade,
  seller_name text not null,
  c           int  not null,              -- カードの ばんごう
  lv          int  not null default 1,
  cores       jsonb not null default '[null,null,null]'::jsonb,
  price       int  not null,
  sold        boolean not null default false,
  created_at  timestamptz not null default now()
);
create index if not exists dm_market_open_idx on public.dm_market (created_at desc) where sold = false;
alter table public.dm_market enable row level security;
revoke all on public.dm_market from anon, authenticated;

-- しゅっぴん中の いちらん (じぶんのも ふくむ)
create or replace function public.dm_market_list(p_token uuid)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare v_me uuid;
begin
  v_me := dm_sess_(p_token);
  if v_me is null then return '[]'::jsonb; end if;
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'id', m.id, 'seller', m.seller_name, 'mine', (m.seller_id = v_me),
      'c', m.c, 'lv', m.lv, 'cores', m.cores, 'price', m.price) order by m.created_at desc)
    from dm_market m where m.sold = false limit 60
  ), '[]'::jsonb);
end $$;

-- しゅっぴんする (クライアント側で もちものから へらしてから よぶ)
create or replace function public.dm_market_sell(p_token uuid, p_c int, p_lv int, p_cores jsonb, p_price int)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare v_me uuid; v_name text; v_cnt int;
begin
  v_me := dm_sess_(p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'msg', 'セッションぎれ'); end if;
  if coalesce(p_price, 0) < 1 or p_price > 999999 then
    return jsonb_build_object('ok', false, 'msg', 'ねだんは 1〜999999'); end if;
  select username into v_name from dm_accounts where id = v_me;
  select count(*) into v_cnt from dm_market where seller_id = v_me and sold = false;
  if v_cnt >= 10 then return jsonb_build_object('ok', false, 'msg', 'しゅっぴんは 10こまで'); end if;
  insert into dm_market (seller_id, seller_name, c, lv, cores, price)
    values (v_me, v_name, p_c, greatest(1, coalesce(p_lv, 1)), coalesce(p_cores, '[null,null,null]'::jsonb), p_price);
  return jsonb_build_object('ok', true);
end $$;

-- かう (うれたら 売り主に お金の おしらせが とどく)
create or replace function public.dm_market_buy(p_token uuid, p_id bigint)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare v_me uuid; v_m dm_market%rowtype; v_cardname text;
begin
  v_me := dm_sess_(p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'msg', 'セッションぎれ'); end if;
  -- 二重購入ふせぎ: sold=false のときだけ とれる
  update dm_market set sold = true
    where id = p_id and sold = false and seller_id <> v_me
    returning * into v_m;
  if not found then
    return jsonb_build_object('ok', false, 'msg', 'もう うれてしまった かも (じぶんのは かえません)');
  end if;
  v_cardname := coalesce(p_id::text, '');
  -- 売り主に だいきんを おくる (うけとりは あいての クライアントが やる)
  insert into dm_gifts (to_id, kind, amount, item)
    values (v_m.seller_id, 'sale', v_m.price, v_m.c::text);
  return jsonb_build_object('ok', true, 'c', v_m.c, 'lv', v_m.lv, 'cores', v_m.cores, 'price', v_m.price, 'seller', v_m.seller_name);
end $$;

-- しゅっぴんを とりけす (アイテムは クライアントが もちものに もどす)
create or replace function public.dm_market_cancel(p_token uuid, p_id bigint)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare v_me uuid; v_m dm_market%rowtype;
begin
  v_me := dm_sess_(p_token);
  if v_me is null then return jsonb_build_object('ok', false, 'msg', 'セッションぎれ'); end if;
  delete from dm_market where id = p_id and seller_id = v_me and sold = false returning * into v_m;
  if not found then return jsonb_build_object('ok', false, 'msg', 'とりけせなかった'); end if;
  return jsonb_build_object('ok', true, 'c', v_m.c, 'lv', v_m.lv, 'cores', v_m.cores);
end $$;

grant execute on function public.dm_market_list(uuid)                        to anon, authenticated;
grant execute on function public.dm_market_sell(uuid, int, int, jsonb, int)  to anon, authenticated;
grant execute on function public.dm_market_buy(uuid, bigint)                 to anon, authenticated;
grant execute on function public.dm_market_cancel(uuid, bigint)              to anon, authenticated;

-- ================================================
-- システムアカウントを つくる (1回だけ 実行)
-- ※ パスワードは ここを 書きかえれば 変えられます
-- ================================================
insert into public.dm_accounts (username, pass_hash)
  values ('システム', crypt('Usasaburosuta', gen_salt('bf')))
  on conflict (username) do nothing;
