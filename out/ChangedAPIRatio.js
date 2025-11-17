"use strict";
// src/ChangedAPIRatio.ts
// AST 기반 API 변경 탐지 전용 유틸
// 제공되는 기능:
//  - extractApiSignature()
//  - collectApiSigs()
//  - computeApiDiff()
//  - computeApiChangesUsingAST()
//  - ApiSignature 타입
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.extractApiSignature = extractApiSignature;
exports.collectApiSigs = collectApiSigs;
exports.computeApiDiff = computeApiDiff;
exports.computeApiChangesUsingAST = computeApiChangesUsingAST;
const ts = __importStar(require("typescript"));
function extractApiSignature(node, src) {
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
            const init = decl.initializer;
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
function collectApiSigs(code) {
    const src = ts.createSourceFile("file.ts", code, ts.ScriptTarget.Latest, true);
    const apis = [];
    function visit(node) {
        const sig = extractApiSignature(node, src);
        if (sig)
            apis.push(sig);
        ts.forEachChild(node, visit);
    }
    visit(src);
    return apis;
}
// ─────────────────────────────────────────────
// 3) prev(기존 코드) vs cur(새 코드)의 API diff 계산
// ─────────────────────────────────────────────
function computeApiDiff(prev, cur) {
    const prevMap = new Map(prev.map((p) => [p.name, p]));
    const curMap = new Map(cur.map((c) => [c.name, c]));
    let added = 0;
    let removed = 0;
    let changed = 0;
    // added
    for (const [name, c] of curMap) {
        if (!prevMap.has(name))
            added++;
    }
    // removed + changed
    for (const [name, p] of prevMap) {
        if (!curMap.has(name)) {
            removed++;
        }
        else {
            const c = curMap.get(name);
            if (p.signature !== c.signature)
                changed++;
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
function computeApiChangesUsingAST(prevCode, curCode) {
    const prevApis = collectApiSigs(prevCode);
    const curApis = collectApiSigs(curCode);
    return computeApiDiff(prevApis, curApis);
}
//# sourceMappingURL=ChangedAPIRatio.js.map