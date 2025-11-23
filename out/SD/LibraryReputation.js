"use strict";
/**
 * Library Reputation (부분 구현)
 *
 * - 이름 기반 취약 패키지 탐지만 수행
 *   (예: vulnerable_pkg_2023 같은 패턴)
 * - 외부 메타데이터(NPM 다운로드 수, CVE, GitHub stars 등)를
 *   연동한 평판 계산은 아직 미구현 상태
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeLibraryReputationFromCode = analyzeLibraryReputationFromCode;
/**
 * 코드 문자열에서 import/require/의존성 이름을 대충 추출해서
 * "악명 높은" 패키지 이름 패턴이 있는지 확인한다.
 *
 * 현재는 논문/프로토타입용으로,
 *   - vulnerable_pkg_2023
 * 처럼 의도적으로 취약하게 만든 패키지 이름만 탐지한다.
 */
function analyzeLibraryReputationFromCode(code) {
    const reasons = [];
    const matches = [];
    const lower = code.toLowerCase();
    // 기본 평판 점수 (대부분의 일반 라이브러리는 중간 정도로 가정)
    let reputation01 = 0.65;
    // 1) 매우 단순한 "이름 기반 취약 패키지" 패턴
    const suspiciousPatterns = [
        /vulnerable[_-]?pkg[_-]?2023/i,
    ];
    for (const rx of suspiciousPatterns) {
        const m = lower.match(rx);
        if (m) {
            const name = m[0];
            matches.push({
                name,
                reason: `Suspicious package name detected: "${name}"`,
            });
            reasons.push(`library-rep: suspicious package "${name}"`);
            // 평판을 강하게 깎는다 (최소 0.1까지 하락)
            reputation01 = Math.min(reputation01, 0.1);
        }
    }
    // 2) TODO(미구현): 실제 라이브러리 메타데이터 기반 평판
    //    - package.json / import 목록에서 패키지 이름 수집
    //    - 외부 DB(NPM, GitHub, CVE 등)의 지표를 조합해 평판 점수 계산
    //    현재 프로토타입에서는 구현하지 않고 고정값 + 이름 기반 패턴만 사용.
    return {
        reputation01,
        matches,
        reasons,
    };
}
//# sourceMappingURL=LibraryReputation.js.map