from __future__ import annotations

# pyright: reportMissingImports=false
from dotenv import load_dotenv

load_dotenv()

import hashlib
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Literal, Optional, Tuple

from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel, Field


# ============================================================
# Config
# ============================================================

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "ledger.sqlite3"

# 互換のため残す（v0.6.0相当のデフォルト想定）
DEFAULT_REPO_ROOT = APP_DIR.parent

# root 解決優先順位:
# 1) ScanRequest.root
# 2) env: LEDGER_REPO_ROOT
# 3) auto-detect: 親ディレクトリを辿って .git / pyproject.toml / requirements.txt を探す
# 4) fallback: DEFAULT_REPO_ROOT（従来互換）
LEDGER_REPO_ROOT_ENV = "LEDGER_REPO_ROOT"

TAG_RE = re.compile(r"NOTE\(vNext\):\s*([a-z0-9_./-]+)", re.IGNORECASE)
DONE_RE = re.compile(r"DONE\(vNext\):\s*([a-z0-9_./-]+)", re.IGNORECASE)

EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
    "build",
}

SCAN_EXTS = {".py", ".md", ".ts", ".tsx", ".js", ".jsx"}

ACTIVE_STATUSES = ("open", "doing", "parked")

ALLOWED_STATUS = {"open", "parked", "doing", "done", "stale"}
PRIORITY_RANGE = (1, 5)


# ============================================================
# DB utilities (SQL only; commit is caller responsibility)
# ============================================================

def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    # 事故ポイント潰し：SQLiteは外部キー制約がデフォルトOFFになりがち
    con.execute("PRAGMA foreign_keys = ON")
    return con


def init_db() -> None:
    with db() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slug TEXT NOT NULL UNIQUE,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                evidence_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'open',
                priority INTEGER NOT NULL DEFAULT 3,
                owner TEXT,
                decision TEXT
            );
            """
        )

        con.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                note_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                line INTEGER NOT NULL,
                snippet TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                UNIQUE(note_id, path, line),
                FOREIGN KEY(note_id) REFERENCES notes(id) ON DELETE CASCADE
            );
            """
        )

        con.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_scan_at TEXT
            );
            """
        )
        con.execute("INSERT OR IGNORE INTO scan_state (id, last_scan_at) VALUES (1, NULL)")

        con.execute(
            """
            CREATE TABLE IF NOT EXISTS file_state (
                path TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL,
                size INTEGER NOT NULL,
                mtime REAL NOT NULL,
                last_seen TEXT NOT NULL
            );
            """
        )

        # v0.6.0+: scan_log（メトリクスの一次資料）
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                scanned_root TEXT NOT NULL,
                full INTEGER NOT NULL,
                files_scanned INTEGER NOT NULL,
                slugs_found INTEGER NOT NULL,
                evidence_added INTEGER NOT NULL,
                done_forced INTEGER NOT NULL,
                stale_marked INTEGER NOT NULL,
                revived_count INTEGER NOT NULL,
                orphan_files_removed INTEGER NOT NULL
            );
            """
        )

        con.commit()


def get_last_scan_at(con: sqlite3.Connection) -> Optional[str]:
    row = con.execute("SELECT last_scan_at FROM scan_state WHERE id = 1").fetchone()
    return row["last_scan_at"] if row else None


def set_last_scan_at(con: sqlite3.Connection, ts: str) -> None:
    con.execute("UPDATE scan_state SET last_scan_at = ? WHERE id = 1", (ts,))


# ============================================================
# Root resolution (汎用化 + MCP配下でも自動で拾える)
# ============================================================

def _auto_detect_project_root(start: Path, max_hops: int = 10) -> Optional[Path]:
    """
    親ディレクトリを辿り、プロジェクトルートっぽい目印を見つけたらそこを返す。
    - .git
    - pyproject.toml
    - requirements.txt
    """
    cur = start
    for _ in range(max_hops):
        if (
            (cur / ".git").exists()
            or (cur / "pyproject.toml").exists()
            or (cur / "requirements.txt").exists()
        ):
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def resolve_root(req_root: Optional[str]) -> Path:
    # 1) request
    if req_root:
        return Path(req_root).expanduser().resolve()

    # 2) env
    env_root = os.environ.get(LEDGER_REPO_ROOT_ENV)
    if env_root:
        return Path(env_root).expanduser().resolve()

    # 3) auto-detect
    detected = _auto_detect_project_root(APP_DIR)
    if detected:
        return detected

    # 4) fallback (v0.6.0互換)
    return DEFAULT_REPO_ROOT


# ============================================================
# Notes / Evidence
# ============================================================

def upsert_note(con: sqlite3.Connection, slug: str, now: str) -> Tuple[int, bool]:
    """
    NOTE/DONE 検出時の upsert。
    v0.5+:
      - stale だったら open に自動復活（revived=True）
    """
    row = con.execute("SELECT id, status FROM notes WHERE slug = ?", (slug,)).fetchone()

    if row:
        revived = False
        if row["status"] == "stale":
            revived = True
            con.execute(
                """
                UPDATE notes
                SET status = 'open',
                    last_seen = ?
                WHERE slug = ?
                """,
                (now, slug),
            )
        else:
            con.execute("UPDATE notes SET last_seen = ? WHERE slug = ?", (now, slug))
        return int(row["id"]), revived

    con.execute(
        """
        INSERT INTO notes (slug, first_seen, last_seen, evidence_count)
        VALUES (?, ?, ?, 0)
        """,
        (slug, now, now),
    )
    note_id = int(con.execute("SELECT id FROM notes WHERE slug = ?", (slug,)).fetchone()["id"])
    return note_id, False


def add_evidence(
    con: sqlite3.Connection,
    note_id: int,
    path: str,
    line: int,
    snippet: str,
    now: str,
) -> bool:
    try:
        con.execute(
            """
            INSERT INTO evidence (note_id, path, line, snippet, detected_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (note_id, path, line, snippet, now),
        )
    except sqlite3.IntegrityError:
        return False

    con.execute(
        """
        UPDATE notes
        SET evidence_count = evidence_count + 1,
            last_seen = ?
        WHERE id = ?
        """,
        (now, note_id),
    )
    return True


def force_done(con: sqlite3.Connection, *, slugs: set[str], now: str) -> int:
    if not slugs:
        return 0

    placeholders = ",".join("?" * len(slugs))
    cur = con.execute(
        f"""
        UPDATE notes
        SET status = 'done',
            last_seen = ?
        WHERE slug IN ({placeholders})
          AND status != 'done'
        """,
        [now, *sorted(slugs)],
    )
    return int(cur.rowcount)


def mark_missing_as_stale(con: sqlite3.Connection, *, seen_slugs: set[str], now: str) -> int:
    if not seen_slugs:
        return 0

    active = ",".join("?" * len(ACTIVE_STATUSES))
    not_in = ",".join("?" * len(seen_slugs))
    cur = con.execute(
        f"""
        UPDATE notes
        SET status = 'stale',
            last_seen = ?
        WHERE status IN ({active})
          AND slug NOT IN ({not_in})
        """,
        [now, *ACTIVE_STATUSES, *sorted(seen_slugs)],
    )
    return int(cur.rowcount)


def insert_scan_log(
    con: sqlite3.Connection,
    *,
    scanned_at: str,
    scanned_root: str,
    full: int,
    files_scanned: int,
    slugs_found: int,
    evidence_added: int,
    done_forced: int,
    stale_marked: int,
    revived_count: int,
    orphan_files_removed: int,
) -> None:
    con.execute(
        """
        INSERT INTO scan_log (
            scanned_at, scanned_root, full,
            files_scanned, slugs_found, evidence_added,
            done_forced, stale_marked, revived_count, orphan_files_removed
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scanned_at,
            scanned_root,
            full,
            files_scanned,
            slugs_found,
            evidence_added,
            done_forced,
            stale_marked,
            revived_count,
            orphan_files_removed,
        ),
    )


# ============================================================
# Hash diff + orphan cleanup
# ============================================================

def iter_source_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in SCAN_EXTS:
            continue
        yield p


def compute_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def list_files_hashdiff(
    con: sqlite3.Connection,
    *,
    root: Path,
    now: str,
) -> tuple[list[Path], set[str]]:
    changed: list[Path] = []
    seen_paths: set[str] = set()

    for p in iter_source_files(root):
        rel = str(p.relative_to(root)).replace("\\", "/")
        seen_paths.add(rel)

        stat = p.stat()
        size = stat.st_size
        mtime = stat.st_mtime

        row = con.execute(
            "SELECT content_hash, size, mtime FROM file_state WHERE path = ?",
            (rel,),
        ).fetchone()

        # size+mtime が一致 -> 変更なし（hash計算すらしない）
        if row and row["size"] == size and row["mtime"] == mtime:
            con.execute("UPDATE file_state SET last_seen = ? WHERE path = ?", (now, rel))
            continue

        h = compute_hash(p)

        # mtimeだけ変わった等（hash一致） -> 更新のみ
        if row and row["content_hash"] == h:
            con.execute(
                """
                UPDATE file_state
                SET size = ?, mtime = ?, last_seen = ?
                WHERE path = ?
                """,
                (size, mtime, now, rel),
            )
            continue

        # 本当に変更あり
        changed.append(p)
        con.execute(
            """
            INSERT INTO file_state (path, content_hash, size, mtime, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
              content_hash = excluded.content_hash,
              size = excluded.size,
              mtime = excluded.mtime,
              last_seen = excluded.last_seen
            """,
            (rel, h, size, mtime, now),
        )

    return changed, seen_paths


def cleanup_orphan_file_state(con: sqlite3.Connection, *, seen_paths: set[str]) -> int:
    """
    full=True のときだけ呼ぶ（世界を閉じた時だけ掃除する）
    """
    if not seen_paths:
        return 0
    placeholders = ",".join("?" * len(seen_paths))
    cur = con.execute(
        f"DELETE FROM file_state WHERE path NOT IN ({placeholders})",
        list(seen_paths),
    )
    return int(cur.rowcount)


# ============================================================
# Scanner
# ============================================================

HitKind = Literal["note", "done"]


@dataclass(frozen=True)
class Hit:
    kind: HitKind
    slug: str
    path: str
    line: int
    snippet: str


def collect_hits_from_files(*, root: Path, files: Iterable[Path]) -> list[Hit]:
    hits: list[Hit] = []
    for f in files:
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue

        rel = str(f.relative_to(root)).replace("\\", "/")
        for i, line in enumerate(lines, start=1):
            m = TAG_RE.search(line)
            if m:
                hits.append(Hit("note", m.group(1).strip(), rel, i, line.strip()))
                continue

            m = DONE_RE.search(line)
            if m:
                hits.append(Hit("done", m.group(1).strip(), rel, i, line.strip()))
                continue

    return hits


# ============================================================
# API
# ============================================================

app = FastAPI(title="vNext Ledger", version="0.6.2")


@app.on_event("startup")
def _startup() -> None:
    init_db()
    # 起動時に root と DB を1発で見える化（事故切り分け用）
    print(f"[vNext-ledger] db={DB_PATH}")
    print(f"[vNext-ledger] resolved_root={resolve_root(None)}")


class ScanRequest(BaseModel):
    root: Optional[str] = Field(default=None, description="repo root (optional)")


class ScanResponse(BaseModel):
    scanned_root: str
    files_scanned: int
    slugs_found: int
    evidence_added: int
    done_forced: int
    stale_marked: int
    revived_count: int
    orphan_files_removed: int


@app.get("/")
def root():
    return {"status": "ok", "message": "vNext ledger is alive"}

@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest = Body(default_factory=ScanRequest), full: bool = False):
    """
    /scan の責務：
      - 入力（files）を得る
      - NOTE/DONE を抽出して台帳に反映する

    安全ルール：
      - full=False（差分）では stale/orphan を絶対に走らせない
      - full=True（全走査）でのみ stale/orphan を走らせる（世界を閉じる）
    """
    root_path = resolve_root(req.root)
    if not root_path.exists() or not root_path.is_dir():
        raise HTTPException(status_code=400, detail=f"Invalid root: {root_path}")

    now = datetime.now().isoformat(timespec="seconds")

    seen_slugs: set[str] = set()
    done_slugs: set[str] = set()

    evidence_added = 0
    stale_marked = 0
    orphan_removed = 0
    revived_count = 0

    with db() as con:
        # 入力戦略
        if full:
            files = list(iter_source_files(root_path))
            seen_paths = {str(p.relative_to(root_path)).replace("\\", "/") for p in files}
        else:
            files, seen_paths = list_files_hashdiff(con, root=root_path, now=now)

        hits = collect_hits_from_files(root=root_path, files=files)

        for h in hits:
            seen_slugs.add(h.slug)
            if h.kind == "done":
                done_slugs.add(h.slug)

            note_id, revived = upsert_note(con, h.slug, now)
            if revived:
                revived_count += 1

            if add_evidence(con, note_id, h.path, h.line, h.snippet, now):
                evidence_added += 1

        # DONE を最優先で収束
        done_forced = force_done(con, slugs=done_slugs, now=now)

        # full のときだけ世界を閉じる
        if full:
            stale_marked = mark_missing_as_stale(con, seen_slugs=seen_slugs, now=now)
            orphan_removed = cleanup_orphan_file_state(con, seen_paths=seen_paths)

        # scan_state 更新
        set_last_scan_at(con, now)

        # scan_log 保存
        insert_scan_log(
            con,
            scanned_at=now,
            scanned_root=str(root_path),
            full=1 if full else 0,
            files_scanned=len(files),
            slugs_found=len(seen_slugs),
            evidence_added=evidence_added,
            done_forced=done_forced,
            stale_marked=stale_marked,
            revived_count=revived_count,
            orphan_files_removed=orphan_removed,
        )

        con.commit()

    return ScanResponse(
        scanned_root=str(root_path),
        files_scanned=len(files),
        slugs_found=len(seen_slugs),
        evidence_added=evidence_added,
        done_forced=done_forced,
        stale_marked=stale_marked,
        revived_count=revived_count,
        orphan_files_removed=orphan_removed,
    )


# ============================================================
# Notes APIs
# ============================================================

@app.get("/notes")
def list_notes(limit: int = 200):
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be 1..1000")

    with db() as con:
        rows = con.execute(
            """
            SELECT slug, evidence_count, status, priority, owner, decision,
                   first_seen, last_seen
            FROM notes
            ORDER BY priority ASC, evidence_count DESC, last_seen DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return {"notes": [dict(r) for r in rows]}


@app.get("/notes/{slug}")
def note_detail(slug: str, limit: int = 200):
    if limit < 1 or limit > 2000:
        raise HTTPException(status_code=400, detail="limit must be 1..2000")

    with db() as con:
        note = con.execute(
            """
            SELECT id, slug, evidence_count, status, priority, owner, decision,
                   first_seen, last_seen
            FROM notes
            WHERE slug = ?
            """,
            (slug,),
        ).fetchone()

        if not note:
            raise HTTPException(status_code=404, detail="not found")

        ev = con.execute(
            """
            SELECT path, line, snippet, detected_at
            FROM evidence
            WHERE note_id = ?
            ORDER BY detected_at DESC
            LIMIT ?
            """,
            (note["id"], limit),
        ).fetchall()

    return {"note": dict(note), "evidence": [dict(r) for r in ev]}


class NotePatch(BaseModel):
    status: Optional[str] = None
    priority: Optional[int] = None
    owner: Optional[str] = None
    decision: Optional[str] = None


@app.patch("/notes/{slug}")
def update_note(slug: str, patch: NotePatch):
    updates: dict[str, object] = {}

    if patch.status is not None:
        if patch.status not in ALLOWED_STATUS:
            raise HTTPException(status_code=400, detail="invalid status")
        updates["status"] = patch.status

    if patch.priority is not None:
        lo, hi = PRIORITY_RANGE
        if patch.priority < lo or patch.priority > hi:
            raise HTTPException(status_code=400, detail=f"priority must be {lo}..{hi}")
        updates["priority"] = patch.priority

    if patch.owner is not None:
        updates["owner"] = patch.owner

    if patch.decision is not None:
        updates["decision"] = patch.decision

    if not updates:
        return {"ok": True, "updated": {}}

    now = datetime.now().isoformat(timespec="seconds")

    with db() as con:
        row = con.execute("SELECT id FROM notes WHERE slug = ?", (slug,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="not found")

        sets = ", ".join([f"{k} = ?" for k in updates.keys()] + ["last_seen = ?"])
        params = list(updates.values()) + [now, slug]
        con.execute(f"UPDATE notes SET {sets} WHERE slug = ?", params)
        con.commit()

        updated = con.execute(
            """
            SELECT slug, evidence_count, status, priority, owner, decision,
                   first_seen, last_seen
            FROM notes
            WHERE slug = ?
            """,
            (slug,),
        ).fetchone()

    return {"ok": True, "note": dict(updated)}


# ============================================================
# Export APIs (read-only, side-effect free)
# ============================================================

@app.get("/export/notes")
def export_notes():
    exported_at = datetime.now().isoformat(timespec="seconds")

    with db() as con:
        notes = con.execute(
            """
            SELECT id, slug, status, priority, owner, decision,
                   first_seen, last_seen, evidence_count
            FROM notes
            ORDER BY priority ASC, evidence_count DESC, last_seen DESC
            """
        ).fetchall()

        result: list[dict[str, Any]] = []
        for n in notes:
            ev = con.execute(
                """
                SELECT path, line, snippet, detected_at
                FROM evidence
                WHERE note_id = ?
                ORDER BY detected_at ASC
                """,
                (n["id"],),
            ).fetchall()

            result.append(
                {
                    "slug": n["slug"],
                    "status": n["status"],
                    "priority": n["priority"],
                    "owner": n["owner"],
                    "decision": n["decision"],
                    "first_seen": n["first_seen"],
                    "last_seen": n["last_seen"],
                    "evidence_count": n["evidence_count"],
                    "evidence": [dict(e) for e in ev],
                }
            )

    return {"exported_at": exported_at, "notes": result}


@app.get("/export/summary")
def export_summary():
    exported_at = datetime.now().isoformat(timespec="seconds")

    with db() as con:
        total = con.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
        rows = con.execute(
            """
            SELECT status, COUNT(*) as cnt
            FROM notes
            GROUP BY status
            """
        ).fetchall()
        last_scan = con.execute("SELECT last_scan_at FROM scan_state WHERE id = 1").fetchone()[
            "last_scan_at"
        ]

    return {
        "exported_at": exported_at,
        "total": total,
        "by_status": {r["status"]: r["cnt"] for r in rows},
        "last_scan_at": last_scan,
    }


@app.get("/export/scan_history")
def export_scan_history(limit: int = 50):
    """
    scan_log の履歴
    """
    if limit < 1 or limit > 2000:
        raise HTTPException(status_code=400, detail="limit must be 1..2000")

    with db() as con:
        rows = con.execute(
            """
            SELECT id, scanned_at, scanned_root, full,
                   files_scanned, slugs_found, evidence_added,
                   done_forced, stale_marked, revived_count, orphan_files_removed
            FROM scan_log
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return {"recent": [dict(r) for r in rows]}


@app.get("/export/metrics")
def export_metrics(limit: int = 50):
    """
    メトリクス（直近 + 集計 + 全期間集計）
    """
    if limit < 1 or limit > 2000:
        raise HTTPException(status_code=400, detail="limit must be 1..2000")

    exported_at = datetime.now().isoformat(timespec="seconds")

    with db() as con:
        recent = con.execute(
            """
            SELECT id, scanned_at, scanned_root, full,
                   files_scanned, slugs_found, evidence_added,
                   done_forced, stale_marked, revived_count, orphan_files_removed
            FROM scan_log
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        agg = con.execute(
            """
            SELECT
              COUNT(*) as runs,
              SUM(CASE WHEN full = 1 THEN 1 ELSE 0 END) as full_runs,
              SUM(CASE WHEN full = 0 THEN 1 ELSE 0 END) as diff_runs,
              COALESCE(SUM(done_forced), 0) as done_forced,
              COALESCE(SUM(stale_marked), 0) as stale_marked,
              COALESCE(SUM(revived_count), 0) as revived_count,
              COALESCE(SUM(orphan_files_removed), 0) as orphan_files_removed,
              COALESCE(SUM(evidence_added), 0) as evidence_added,
              COALESCE(SUM(files_scanned), 0) as files_scanned,
              COALESCE(SUM(slugs_found), 0) as slugs_found
            FROM (
              SELECT done_forced, stale_marked, revived_count, orphan_files_removed,
                     evidence_added, files_scanned, slugs_found, full
              FROM scan_log
              ORDER BY id DESC
              LIMIT ?
            )
            """,
            (limit,),
        ).fetchone()

        agg_all = con.execute(
            """
            SELECT
              COUNT(*) as runs,
              SUM(CASE WHEN full = 1 THEN 1 ELSE 0 END) as full_runs,
              SUM(CASE WHEN full = 0 THEN 1 ELSE 0 END) as diff_runs,
              COALESCE(SUM(done_forced), 0) as done_forced,
              COALESCE(SUM(stale_marked), 0) as stale_marked,
              COALESCE(SUM(revived_count), 0) as revived_count,
              COALESCE(SUM(orphan_files_removed), 0) as orphan_files_removed,
              COALESCE(SUM(evidence_added), 0) as evidence_added,
              COALESCE(SUM(files_scanned), 0) as files_scanned,
              COALESCE(SUM(slugs_found), 0) as slugs_found
            FROM scan_log
            """
        ).fetchone()

        last_scan = con.execute("SELECT last_scan_at FROM scan_state WHERE id = 1").fetchone()[
            "last_scan_at"
        ]

    return {
        "exported_at": exported_at,
        "last_scan_at": last_scan,
        "limit": limit,
        "recent": [dict(r) for r in recent],
        "aggregate": dict(agg) if agg else {},
        "aggregate_all": dict(agg_all) if agg_all else {},
        "resolved_root": str(resolve_root(None)),
        "root_resolution": {
            "order": [
                "request.root",
                f"env.{LEDGER_REPO_ROOT_ENV}",
                "auto_detect(.git/pyproject.toml/requirements.txt)",
                "fallback(DEFAULT_REPO_ROOT)",
            ]
        },
    }
