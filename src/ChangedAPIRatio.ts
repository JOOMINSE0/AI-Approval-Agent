// src/ChangedAPIRatio.ts
// AST 기반 API 변경 탐지 전용 유틸
// 제공되는 기능:
//  - extractApiSignature()
//  - collectApiSigs()
//  - computeApiDiff()
//  - computeApiChangesUsingAST()
//  - ApiSignature 타입

import * as ts from "typescript";

// ─────────────────────────────────────────────
// 1) 함수/클래스/인터페이스/타입 등 시그니처 추출
// ─────────────────────────────────────────────

export type ApiSignature = {
  kind: "function" | "class" | "interface" | "type" | "var";
  name: string;
  signature: string;
};

export function extractApiSignature(node: ts.Node, src: ts.SourceFile): ApiSignature | null {
  // function foo() {}
  if (ts.isFunctionDeclaration(node) && node.name) {
    return {
      kind: "function",
      name: node.name.getText(src),
      signature: node.getText(src)
    };
  }

  // const foo = () => {}
  if (ts.isVariableStatement(node)) {
    for (const decl of node.declarationList.declarations) {
      const name = decl.name.getText(src);
      const init = (decl as any).initializer;
      if (init && (ts.isArrowFunction(init) || ts.isFunctionExpression(init))) {
        return {
          kind: "var",
          name,
          signature: node.getText(src)
        };
      }
    }
  }

  // class Foo {}
  if (ts.isClassDeclaration(node) && node.name) {
    return {
      kind: "class",
      name: node.name.getText(src),
      signature: node.getText(src)
    };
  }

  // interface Foo {}
  if (ts.isInterfaceDeclaration(node)) {
    return {
      kind: "interface",
      name: node.name.getText(src),
      signature: node.getText(src)
    };
  }

  // type Foo = ...
  if (ts.isTypeAliasDeclaration(node)) {
    return {
      kind: "type",
      name: node.name.getText(src),
      signature: node.getText(src)
    };
  }

  return null;
}

// ─────────────────────────────────────────────
// 2) 전체 코드에서 API 시그니처 목록 수집
// ─────────────────────────────────────────────

export function collectApiSigs(code: string): ApiSignature[] {
  const src = ts.createSourceFile("file.ts", code, ts.ScriptTarget.Latest, true);
  const apis: ApiSignature[] = [];

  function visit(node: ts.Node) {
    const sig = extractApiSignature(node, src);
    if (sig) apis.push(sig);
    ts.forEachChild(node, visit);
  }
  visit(src);

  return apis;
}

// ─────────────────────────────────────────────
// 3) prev(기존 코드) vs cur(새 코드)의 API diff 계산
// ─────────────────────────────────────────────

export function computeApiDiff(prev: ApiSignature[], cur: ApiSignature[]) {
  const prevMap = new Map(prev.map((p) => [p.name, p]));
  const curMap = new Map(cur.map((c) => [c.name, c]));

  let added = 0;
  let removed = 0;
  let changed = 0;

  // added
  for (const [name, c] of curMap) {
    if (!prevMap.has(name)) added++;
  }

  // removed + changed
  for (const [name, p] of prevMap) {
    if (!curMap.has(name)) {
      removed++;
    } else {
      const c = curMap.get(name)!;
      if (p.signature !== c.signature) changed++;
    }
  }

  return {
    added,
    removed,
    changed,
    apiChanges: added + removed + changed,
    totalApis: Math.max(prev.length, cur.length)
  };
}

// ─────────────────────────────────────────────
// 4) 최종 Helper: 코드 문자열 2개를 받아 API 변화량 계산
// ─────────────────────────────────────────────

export function computeApiChangesUsingAST(prevCode: string, curCode: string) {
  const prevApis = collectApiSigs(prevCode);
  const curApis = collectApiSigs(curCode);
  return computeApiDiff(prevApis, curApis);
}
