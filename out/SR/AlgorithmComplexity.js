"use strict";
// src/AlgorithmComplexity.ts
Object.defineProperty(exports, "__esModule", { value: true });
exports.mapBigOTo01 = mapBigOTo01;
exports.analyzeAlgorithmComplexity = analyzeAlgorithmComplexity;
// Big-O를 0~1 스케일로 매핑
function mapBigOTo01(bigO) {
    const lut = {
        "O(1)": 0.05,
        "O(log n)": 0.15,
        "O(n)": 0.20,
        "O(n log n)": 0.35,
        "O(n^2)": 0.70,
        "O(n^3)": 0.90,
        unknown: 0.50,
    };
    return lut[bigO] ?? 0.5;
}
// 코드에서 알고리즘 복잡도 관련 특징을 추출
function analyzeAlgorithmComplexity(code) {
    const branches = (code.match(/\b(if|else if|case|catch|&&|\|\||\?[:]|for|while|switch|try)\b/g) || [])
        .length;
    const loopCount = (code.match(/\b(for|while|forEach|map\(|reduce\()/g) || []).length;
    const nestedLoop = /\b(for|while)\s*\([^)]*\)\s*{[^{}]*\b(for|while)\s*\(/s.test(code);
    const tripleNested = /\b(for|while)[\s\S]{0,300}\b(for|while)[\s\S]{0,300}\b(for|while)/s.test(code);
    const loopDepthApprox = tripleNested ? 3 : nestedLoop ? 2 : loopCount > 0 ? 1 : 0;
    const sortHint = /\b(sort\(|Collections\.sort|Arrays\.sort)\b/.test(code);
    const recursion = /function\s+([A-Za-z0-9_]+)\s*\([^)]*\)\s*{[\s\S]*?\b\1\s*\(/.test(code) ||
        /([A-Za-z0-9_]+)\s*=\s*\([^)]*\)\s*=>[\s\S]*?\b\1\s*\(/.test(code);
    const divideAndConquerHint = recursion && /\b(mid|merge|partition|divide|conquer)\b/i.test(code);
    const regexDosHint = /(a+)+|(\.\*){2,}|(.*){2,}/.test(code) &&
        /(re\.compile|new\s+RegExp)/.test(code);
    let bigO = "unknown";
    if (loopDepthApprox >= 3)
        bigO = "O(n^3)";
    else if (loopDepthApprox === 2)
        bigO = "O(n^2)";
    else if (sortHint || divideAndConquerHint)
        bigO = "O(n log n)";
    else if (loopDepthApprox === 1 || recursion)
        bigO = "O(n)";
    else
        bigO = "unknown";
    return {
        bigO,
        loopCount,
        loopDepthApprox,
        recursion,
        divideAndConquerHint,
        sortHint,
        regexDosHint,
    };
}
//# sourceMappingURL=AlgorithmComplexity.js.map