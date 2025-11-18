"use strict";
// src/SR/MemoryAllocationIncrease.ts
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeMemoryAllocationIncrease = analyzeMemoryAllocationIncrease;
/**
 * Memory Allocation Increase 분석
 *
 * - Buffer.alloc(size)
 * - new Array(n), Array(n).fill(...)
 * - 배열 리터럴 [...]
 * - 객체 리터럴 { ... }
 * - new Map(), new Set()
 *
 * 등을 기준으로 "할당 횟수 + 바이트"를 대략 추정해서 반환
 */
function analyzeMemoryAllocationIncrease(code) {
    let memBytesApprox = 0;
    const reasons = [];
    const inc = (n, reason) => {
        const v = Math.max(0, n);
        memBytesApprox += v;
        if (reason)
            reasons.push(reason);
    };
    // 1) Buffer.alloc(size)
    const bufAlloc = [...code.matchAll(/Buffer\.alloc\s*\(\s*(\d+)\s*\)/gi)];
    bufAlloc.forEach((m) => {
        const size = parseInt(m[1], 10) || 0;
        inc(size, `Buffer.alloc(${size})`);
    });
    // 2) new Array(n), Array(n).fill(...)
    const arrAlloc = [...code.matchAll(/\bnew\s+Array\s*\(\s*(\d+)\s*\)|\bArray\s*\(\s*(\d+)\s*\)\.fill/gi)];
    arrAlloc.forEach((m) => {
        const n = parseInt(m[1] || m[2], 10) || 0;
        // 요소당 8바이트 정도로 러프하게 가정
        inc(n * 8, `Array(${n}) allocation`);
    });
    // 3) 문자열 리터럴 길이
    const strLits = [...code.matchAll(/(["'`])([^"'`\\]|\\.){1,200}\1/g)];
    strLits.forEach((m) => {
        inc(m[0]?.length || 0);
    });
    // 4) 배열 리터럴 [a, b, c, ...]
    const arrayLits = [...code.matchAll(/\[([^\[\]]{0,400})\]/g)];
    arrayLits.forEach((m) => {
        const elems = m[1].split(",").length || 0;
        // 요소당 16바이트 정도로 러프하게 가정
        inc(elems * 16, `Array literal with ~${elems} elements`);
    });
    // 5) 객체 리터럴 { a: 1, b: 2, ... }
    const objectLits = [...code.matchAll(/\{([^{}]{0,400})\}/g)];
    objectLits.forEach((m) => {
        const props = (m[1].match(/:/g) || []).length;
        // 프로퍼티당 24바이트 정도 가정
        inc(props * 24, `Object literal with ~${props} props`);
    });
    // 6) Map / Set
    const mapSetCount = (code.match(/\bnew\s+(Map|Set)\s*\(/g) || []).length;
    if (mapSetCount > 0) {
        inc(mapSetCount * 128, `new Map/Set x${mapSetCount}`);
    }
    const memAllocs = bufAlloc.length +
        arrAlloc.length +
        arrayLits.length +
        objectLits.length +
        mapSetCount;
    return { memAllocs, memBytesApprox, reasons };
}
//# sourceMappingURL=MemoryAllocationIncrease.js.map