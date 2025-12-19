# vNext Ledger — README（日本語 / 完全統合版）

> **keep the future from evaporating**  
> 未来を蒸発させるな。設計の「次」を台帳に固定せよ。

> **A starter kit for solo infrastructure engineers**  
> 一人基盤おじさんスターターパック

vNext Ledger は、コードやドキュメントに散在する  
`NOTE(vNext): ...` / `DONE(vNext): ...` を収集し、  
**「まだやらないが、忘れてはいけない設計判断」**を台帳化する  
ローカル運用基盤です。

Jira でも Notion でもありません。  
**リポジトリを一次情報として扱うための、最小の設計 OS**です。

---

## 0. これは何を壊し、何を守るのか

### 壊すもの

- TODO コメントが死ぬ文化  
  （見えない／消える／意味が蒸発する）
- 「今じゃない」という判断が履歴に残らない文化
- 技術負債がチケットに堕ち、文脈を失う構造
- 責任の所在が不明なまま時間だけが進む運用

### 守るもの

- 設計者の意思決定
- 将来の自分の回復能力
- 責任線（誰が・何を・なぜ決めたか）

> 人を責めない。  
> 文明を修復する。  
> 忘れる仕組みを、忘れない構造に置き換える。

---

## 1. vNext Ledger とは？

vNext Ledger は **タスク管理ツールではありません**。

これは  
**「設計メモの保存・観測・収束」を行うための基盤**です。

- `NOTE(vNext): retry-policy` のようなタグを収集
- 出現箇所（evidence）を **単一ファイルの SQLite に永続化**
- `status / priority / owner / decision` を付与
- 差分 scan により運用コストを最小化

「今はやらない」という判断を、  
**意思決定として正しく保存するための装置**です。

---

## 2. 5分で動かす

### 2.1 起動

```powershell
cd vnext-ledger
.\.venv\Scripts\Activate.ps1
python -m uvicorn app:app --reload
```

起動時、以下が stdout に表示されます：

- DB の場所
- 解決された scan root

これは **環境変数・cwd・パス事故の即時切り分け**のためです。

---

### 2.2 scan（副作用あり）

```bash
curl -X POST "http://127.0.0.1:8000/scan"
```

- デフォルトは **差分 scan**
- 変更されたファイルのみを観測
- 既存の世界を壊しません

#### 全走査（収束操作）

```bash
curl -X POST "http://127.0.0.1:8000/scan?full=1"
```

---

### scan の安全ルール（重要）

- `full=0`（デフォルト）  
  → **差分観測のみ**。stale / orphan を触らない

- `full=1`  
  → **全走査＋収束操作**  
     - missing note を stale にする  
     - 孤立 file_state を削除する  

⚠️ **`full=1` は「世界を閉じる操作」です。**  
定期実行・CI・自動化では使用しないでください。

---

### 2.3 台帳を見る

```bash
curl "http://127.0.0.1:8000/notes"
curl "http://127.0.0.1:8000/notes/<slug>"
```

---

### 2.4 意思決定を刻む（PATCH）

```bash
curl -X PATCH "http://127.0.0.1:8000/notes/retry-policy" \
  -H "Content-Type: application/json" \
  -d '{
    "status":"doing",
    "priority":1,
    "owner":"me",
    "decision":"指数バックオフを採用"
  }'
```

- **「やらない決定」も decision として残す**
- decision が埋まったら status を進める

---

### 2.5 JSON のログを見る（scan_log / metrics）

vNext Ledger は、scan 実行のたびに **scan_log（メトリクスの一次資料）**を SQLite に保存します。  
そしてそれを **JSON として読み出せる export API** を持ちます。

- `/export/scan_history`：直近の scan 実行履歴（いつ・どの root・full か・件数）
- `/export/metrics`：直近 N 回の履歴 + 集計（直近集計 / 全期間集計） + resolved_root など

#### 例：直近の scan 履歴

```bash
curl "http://127.0.0.1:8000/export/scan_history?limit=20"
```

#### 例：メトリクス（直近50回 + 集計）

```bash
curl "http://127.0.0.1:8000/export/metrics?limit=50"
```

`/export/metrics` は以下を返します（抜粋）：

- `recent`：直近 N 回の実行レコード（files_scanned / slugs_found / evidence_added など）
- `aggregate`：直近 N 回の集計（runs / full_runs / diff_runs / evidence_added 合計 など）
- `aggregate_all`：全期間の集計
- `last_scan_at`：最終 scan 時刻
- `resolved_root`：現在の root 解決結果
- `root_resolution.order`：root の解決優先順位（仕様の自己記述）

> つまり CLI で JSON を叩くだけで、  
> 「最近 diff だけ回しているか？」「full をいつ打ったか？」「evidence が増えているか？」が即わかります。

（オプション）`jq` があるなら見やすく整形できます：

```bash
curl -s "http://127.0.0.1:8000/export/metrics?limit=50" | jq .
```



---

## 3. コメント規約（入力はコード）

```ts
// NOTE(vNext): auth-model-v2
// NOTE(vNext): retry-policy
// DONE(vNext): legacy-auth
```

- `NOTE(vNext)`  
  → **今はやらないが、忘れてはいけない**

- `DONE(vNext)`  
  → **設計上の決着宣言**

scan 時、`DONE(vNext)` は  
常に **最優先で `done` に収束**されます。

---

## 4. 走査ルートの決定順（重要）

scan 対象の root は、以下の優先順位で解決されます：

1. `POST /scan` の `root`
2. 環境変数 `LEDGER_REPO_ROOT`
3. 自動検出  
   (`.git / pyproject.toml / requirements.txt`)
4. fallback（互換用）

### 例

`.env` に以下を設定：

```env
LEDGER_REPO_ROOT=../MCP
```

すると：

- `MCP/mcp`
- `MCP/tests`

などを横断して走査できます。

---

## 5. これはチケットの代わりではない

- Jira / GitHub Issues  
  → **タスク・進行管理**

- vNext Ledger  
  → **設計判断の蒸発防止装置**

ここを混ぜると、**両方が死にます**。

---

## 6. 設計思想（短く）

- 観測と収束を分離する
- 破壊的操作は明示的にする
- DB ユーティリティは SQL だけを書く
- commit の責任は呼び出し側に置く
- 人ではなく構造で事故を防ぐ

---

## 7. License

MIT License

---

## 最後に（比喩の注意）

> “keep the future from evaporating” は比喩です。

未来の仕事を増やすための道具ではありません。  
**未来の回復力を残すための道具**です。

忘れることを責めない。  
忘れない構造を用意する。

それが vNext Ledger の役割です。
