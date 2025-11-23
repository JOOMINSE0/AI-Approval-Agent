import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";

/**
 * SD: CVE 취약점 스캔용 타입 정의
 */
export type Rule = { rx: string; w: number; note?: string; token?: string; support?: number; idf?: number };
export type TokenizerRule = { name?: string; rx: string; w?: number };

export type Sig = {
  id: string;
  title: string;
  baseSeverity: number;
  rules: Rule[];
  cooccur?: { all: string[]; bonus: number }[];
  proximity?: { a: string; b: string; lines: number; bonus: number }[];
  negatives?: { rx: string; penalty: number; note?: string }[];
  group?: string;
  support_docs?: number;
  tokenizer_rules?: TokenizerRule[];
};

export type CveVectorSig = {
  id: string;
  title: string;
  tokens: Record<string, number>;
  baseSeverity: number;
  notes?: string;
  token_regex?: TokenizerRule[];
};

/**
 * 전역 DB (정규식 룰 / 벡터 시그니처)
 *  - extension.ts 쪽에서 길이 로그를 찍을 수 있도록 export
 */
export let RULE_DB: Sig[] = [];
export let DYN_CVE_DB: CveVectorSig[] = [];

/** 0~1 범위로 클램핑하는 유틸 */
const clamp01 = (x: number) => Math.max(0, Math.min(1, x));

/**
 * generated_cve_rules.json 로드
 *  - RULE_DB 전역을 채우고, 로드된 배열을 그대로 반환
 */
export function loadGeneratedRuleDb(ctx?: vscode.ExtensionContext): Sig[] {
  try {
    const base = ctx ? ctx.extensionUri.fsPath : process.cwd();
    const p = path.join(base, "cve_data", "generated_cve_rules.json");
    if (!fs.existsSync(p)) {
      RULE_DB = [];
      return [];
    }
    const raw = fs.readFileSync(p, "utf8");
    const obj = JSON.parse(raw);
    const arr = (obj?.signatures as Sig[] | undefined) || [];
    RULE_DB = arr;
    // 전역 토크나이저 룰도 보관
    (RULE_DB as any).tokenizer_rules = obj?.tokenizer_rules || [];
    return arr;
  } catch (e) {
    console.error("[CVE] loadGeneratedRuleDb error:", e);
    RULE_DB = [];
    return [];
  }
}

/**
 * generated_cve_db.json 로드
 *  - DYN_CVE_DB 전역을 채우고, 로드된 배열을 그대로 반환
 */
export function loadGeneratedCveDb(ctx?: vscode.ExtensionContext): CveVectorSig[] {
  try {
    const base = ctx ? ctx.extensionUri.fsPath : process.cwd();
    const p = path.join(base, "cve_data", "generated_cve_db.json");
    if (!fs.existsSync(p)) {
      DYN_CVE_DB = [];
      return [];
    }
    const raw = fs.readFileSync(p, "utf8");
    const arr = JSON.parse(raw) as CveVectorSig[];
    DYN_CVE_DB = Array.isArray(arr) ? arr : [];
    return DYN_CVE_DB;
  } catch (e) {
    console.error("[CVE] loadGeneratedCveDb error:", e);
    DYN_CVE_DB = [];
    return [];
  }
}

/** 내부에서 사용할 시그니처 DB getter */
function getSigDB(): CveVectorSig[] {
  return Array.isArray(DYN_CVE_DB) ? DYN_CVE_DB : [];
}

/** 토큰화에 사용할 정규식 패턴 수집 */
function collectTokenizerPatterns() {
  const globalRules: TokenizerRule[] = [];
  const rootRules = (RULE_DB as any)?.tokenizer_rules as TokenizerRule[] | undefined;
  if (Array.isArray(rootRules)) globalRules.push(...rootRules);

  for (const sig of RULE_DB || []) {
    const arr = sig.tokenizer_rules as TokenizerRule[] | undefined;
    if (Array.isArray(arr)) globalRules.push(...arr);
  }

  const perSigRegex: TokenizerRule[] = [];
  for (const sig of DYN_CVE_DB || []) {
    const arr = sig.token_regex as TokenizerRule[] | undefined;
    if (Array.isArray(arr)) perSigRegex.push(...arr);
  }

  return { globalRules, perSigRegex };
}

/** 코드 문자열을 토큰 벡터로 변환 */
function vectorizeCodeToTokens(code: string): Record<string, number> {
  const lower = code.toLowerCase();
  const feats: Record<string, number> = {};
  const add = (k: string, w = 1) => { feats[k] = (feats[k] ?? 0) + w; };

  const sigDB = getSigDB();
  if (sigDB.length) {
    for (const sig of sigDB) {
      const tokTable = sig.tokens || {};
      for (const [tok, wRaw] of Object.entries(tokTable)) {
        const w = typeof wRaw === "number" ? wRaw : 1;
        if (!tok) continue;
        const esc = tok.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const wordLike = /^[A-Za-z0-9_]+$/.test(tok);
        const re = wordLike ? new RegExp(`\\b${esc}\\b`, "i") : new RegExp(esc, "i");
        if (re.test(lower)) add(tok, w);
      }
    }
  }

  const { globalRules, perSigRegex } = collectTokenizerPatterns();
  for (const r of [...globalRules, ...perSigRegex]) {
    if (!r?.rx) continue;
    try {
      const re = new RegExp(r.rx, "i");
      if (re.test(lower)) add(r.name || r.rx, r.w ?? 1);
    } catch {
      // ignore bad regex
    }
  }

  return feats;
}

/** 코사인 유사도 */
function cosineSim(a: Record<string, number>, b: Record<string, number>): number {
  let dot = 0, na = 0, nb = 0;
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const k of keys) {
    const va = a[k] ?? 0;
    const vb = b[k] ?? 0;
    dot += va * vb;
    na += va * va;
    nb += vb * vb;
  }
  if (!na || !nb) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

/**
 * 벡터 기반 CVE 스캔
 *  - 코드 토큰 벡터 vs CVE 벡터 DB 코사인 유사도로 취약점 위험 추정
 */
export function vectorCveScan(code: string) {
  const DB = getSigDB();
  if (!DB.length) return { aggregatedSeverity01: 0, matches: [] as any[] };

  const codeVec = vectorizeCodeToTokens(code);
  const results = DB.map((sig) => {
    const sim = cosineSim(codeVec, sig.tokens || {});
    const base = clamp01(sig.baseSeverity ?? 0.7);
    const sev = clamp01(
      base * Math.min(1, Math.pow(Math.max(0, sim), 0.8) * 1.2)
    );
    return { id: sig.id, title: sig.title, similarity: sim, severity01: sev, notes: sig.notes ?? "" };
  }).sort((a, b) => b.severity01 - a.severity01);

  const topK = results.slice(0, 3);
  let agg = 0;
  for (const r of topK) agg = 1 - (1 - agg) * (1 - r.severity01);

  return {
    aggregatedSeverity01: Math.min(1, agg),
    matches: results.filter((r) => r.similarity > 0.15).slice(0, 5)
  };
}

/**
 * 정규식 룰 기반 CVE 스캔
 *  - RULE_DB를 이용해 코드 내 취약 패턴을 찾고, 심각도(severity01)를 계산
 */
export function regexHeuristicScoreFromDB(code: string, db: Sig[]) {
  if (!db?.length) return { severity01: 0, matches: [] as any[] };

  const lower = code.toLowerCase();
  const lines = lower.split(/\r?\n/);
  const RX = (rx: string) => new RegExp(rx, "i");

  const results = db.map((sig) => {
    let raw = 0;
    const matched: string[] = [];

    for (const r of sig.rules || []) {
      try {
        const re = RX(r.rx);
        if (re.test(lower)) {
          const w = (r.w ?? 1) * (r.idf ?? 1);
          raw += w;
          matched.push(r.token || r.rx);
        }
      } catch {
        // ignore bad regex
      }
    }

    sig.cooccur?.forEach((c) => {
      const ok = (c.all || []).every((rx) => { try { return RX(rx).test(lower); } catch { return false; } });
      if (ok) raw += c.bonus || 0;
    });

    sig.proximity?.forEach((p) => {
      try {
        const A = RX(p.a), B = RX(p.b);
        const L = p.lines ?? 5;
        for (let i = 0; i < lines.length; i++) {
          if (!A.test(lines[i])) continue;
          for (let d = -L; d <= L; d++) {
            const j = i + d;
            if (j >= 0 && j < lines.length && B.test(lines[j])) { raw += p.bonus || 0; d = L + 1; break; }
          }
        }
      } catch {
        // ignore
      }
    });

    sig.negatives?.forEach((n) => { try { if (RX(n.rx).test(lower)) raw -= n.penalty || 0; } catch {} });

    const base = clamp01(sig.baseSeverity ?? 0.7);
    const supBoost = Math.min(0.10, (Math.max(0, sig.support_docs ?? 0) / 1000));
    const sev = clamp01((base * (1 + supBoost)) * (1 - Math.exp(-3 * Math.max(0, raw))));

    return { id: sig.id, title: sig.title, severity01: sev, matched, raw: Number(Math.max(0, raw).toFixed(3)) };
  }).sort((a, b) => b.severity01 - a.severity01);

  const topK = results.slice(0, 3);
  let agg = 0;
  for (const r of topK) agg = 1 - (1 - agg) * (1 - r.severity01);

  return {
    severity01: clamp01(agg),
    matches: results.filter((r) => r.severity01 > 0.15).slice(0, 5)
  };
}
