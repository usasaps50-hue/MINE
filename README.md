# デッキと慈悲(仮)

GitHub Pages + Supabase で動くカードバトルゲーム。
ひとりでも、あいことばで つながって **ふたり協力バトル** でも遊べる。

## ファイル構成

| ファイル | 役割 |
|---|---|
| `index.html` | ゲーム本体 (全部入り) |
| `config.js` | Supabase の接続先設定 (自分のものに書きかえる) |
| `schema.sql` | Supabase に流すデータベース設定 |

## セットアップ手順

### 1. Supabase 側

1. https://supabase.com で無料アカウントを作り、新しいプロジェクトを作る
2. 左メニュー **SQL Editor** → `schema.sql` の中身を全部貼りつけて **Run**
3. 左メニュー **Settings → API** を開き、
   - **Project URL**
   - **anon public** キー
   をコピー
4. `config.js` を開いて貼りかえる:

```js
window.DM_CONFIG = {
  SUPABASE_URL: 'https://xxxxxxxx.supabase.co',
  SUPABASE_ANON_KEY: 'eyJhbGciOi...'
};
```

※ anon キーは公開前提のキーなので GitHub に上げてOK。
データ保護は Supabase 側 (RLS + RPC関数) でやっている。

### 2. GitHub Pages 側

```sh
# このフォルダで (初回)
git init
git add .
git commit -m "first commit"
gh repo create deck-and-mercy --public --source=. --push
# または github.com で空リポジトリを作って:
# git remote add origin https://github.com/あなたの名前/deck-and-mercy.git
# git push -u origin main
```

GitHub のリポジトリページ → **Settings → Pages** →
Branch を `main` / `(root)` にして Save。
数分後 `https://あなたの名前.github.io/deck-and-mercy/` で遊べる。

## BAN のやり方

Supabase の **Table Editor → dm_accounts** で、
止めたいユーザーの `banned` 列を `true` にするだけ。
プレイ中でも数秒以内に「アカウントが ていしされました」でログイン画面に戻される。

## ふたり協力バトルの遊びかた

1. ふたりともログインして メニュー → **きょうりょくバトル**
2. ひとりが「へやを つくる」→ 4けたの **あいことば** が出る
3. もうひとりが あいことばを入れて「はいる」
4. ふたりとも「たたかう」を押すとスタート
   (WORLD/WAVE は ふたりのうち **すすみが低いほう** に自動で合わせられる)

- 敵のHPゲージは **ふたりで共有**。どちらの攻撃でも削れる
- 自分のHPは別々。敵の攻撃タップ回避パートは **ふたりとも** やってくる
- 右上の小窓に、なかまのHP・攻撃・被ダメージ・クリティカルがリアルタイムで見える
- ダウンしたら: 生きてる方はデッキ下の **アイテム「ふっかつ」** を使い、
  バーを **ジャスト (クリティカル)** で止められれば HP50% で復活させられる
- ふたりとも倒れたら全滅 (進みはそのまま)

## 技術メモ

- 認証/セーブ: Supabase RPC (`dm_register` / `dm_login` / `dm_check` / `dm_save`)。
  パスワードは bcrypt でハッシュ化。テーブル直アクセスは RLS で全面禁止
- 協力プレイ: Supabase Realtime の broadcast + presence (`dm-room-あいことば` チャンネル)。
  サーバー側のテーブルは使わないので部屋の後かたづけ不要
