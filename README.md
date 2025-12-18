# vNext Ledger — README（日本語 / 完全統合版）

> **keep the future from evaporating**  
> 未来を蒸発させるな。設計の「次」を台帳に固定せよ。

> **A starter kit for solo infrastructure engineers**  
> 一人基盤おじさんスターターパック

vNext Ledger は、コードやドキュメントに散在する `NOTE(vNext): ...` を収集し、
**「まだやらないが、忘れてはいけない」設計負債**を台帳化するローカル運用基盤です。  
Jira でも Notion でもなく、**リポジトリを一次情報として扱うための最小 OS**です。

---

## 0. これは何を壊し、何を守るのか

### 壊すもの

- TODO コメントが死ぬ文化（見えない／消える／意味が消滅する）
- 「今じゃない」という判断が履歴に残らない文化
- 技術負債がチケットに堕ちて文脈を失う文化

### 守るもの

- 設計者の意思決定
- 将来の自分の回復能力
- 責任線（誰が何を決めたか）

> 人を責めない。文明を修復する。  
> 忘れる仕組みを、忘れない構造に置き換える。

---

## 1. vNext Ledger とは？

vNext Ledger は **タスク管理ツールではありません**。  
これは **設計メモの保存と運用** のための基盤です。

- `NOTE(vNext): retry-policy` のようなタグを収集
- 出現箇所（evidence）を DB に保存
- `status / priority / owner / decision` を付与して台帳化
- 差分 scan により運用コストを最小化

---

## 2. 5分で動かす

### 2.1 起動

```powershell
cd vnext-ledger
.\.venv\Scripts\Activate.ps1
python -m uvicorn app:app --reload
```

### 2.2 scan（副作用あり）

```bash
curl -X POST "http://127.0.0.1:8000/scan"
```

差分 scan（通常）／全量 scan（たまに）：

```bash
curl -X POST "http://127.0.0.1:8000/scan?full=1"
```

### 2.3 台帳を見る

```bash
curl "http://127.0.0.1:8000/notes"
curl "http://127.0.0.1:8000/notes/<slug>"
```

### 2.4 意思決定を刻む（PATCH）

```bash
curl -X PATCH "http://127.0.0.1:8000/notes/retry-policy" \
  -H "Content-Type: application/json" \
  -d '{"status":"doing","priority":1,"owner":"me","decision":"指数バックオフ採用"}'
```

---

## 3. コメント規約（入力はコード）

```ts
// NOTE(vNext): auth-model-v2
// NOTE(vNext): retry-policy
```

- `NOTE(vNext)` は「今やらない」を許す
- `decision` を埋めたら `status` を進める
- **「やらない決定」も decision として残す**

---

## 4. これはチケットの代わりではない

- Jira / Issues → **タスク**
- vNext Ledger → **設計の蒸発防止装置**

ここを混ぜると、両方死ぬ。

---

## 5. License

MIT License

---

## 最後に（比喩の注意）

> “keep the future from evaporating” は比喩です。

未来の仕事を増やすための道具ではありません。  
**未来の回復力を残すための道具**です。

