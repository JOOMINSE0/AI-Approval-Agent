/**
 * 4. Sensitive Permission Usage
 *
 * OS 명령 실행(exec, spawn 등), 파일 시스템 접근(fs.*),
 * 시크릿/크리덴셜 접근(process.env, secret, password 등)을
 * 정규식으로 탐지해서 0~1 범위의 permRisk01 점수로 반환한다.
 */

export type SensitivePermissionUsageResult = {
  permRisk01: number;   // 0(안전) ~ 1(위험)
  reasons: string[];    // 탐지 근거 메시지 (UI/로그용)
};

const clamp01 = (x: number) => Math.max(0, Math.min(1, x));

export function analyzeSensitivePermissionUsageFromCode(
  code: string
): SensitivePermissionUsageResult {
  const reasons: string[] = [];
  const lower = code.toLowerCase();
  let permRisk = 0;

  // 1) OS 명령 실행 관련 API 사용 (child_process, exec, spawn, system, popen, subprocess 등)
  if (/\b(child_process|exec\(|spawn\(|system\(|popen\(|subprocess\.)/i.test(code)) {
    permRisk += 0.4;
    reasons.push(
      "perm: OS command execution API (child_process/exec/spawn/system/popen/subprocess) detected"
    );
  }

  // 2) 파일 시스템 접근 (fs.read/write/unlink/chmod/chown/readdir 등)
  if (/\bfs\.(read|write|unlink|chmod|chown|readdir)\b/i.test(code)) {
    permRisk += 0.3;
    reasons.push(
      "perm: filesystem access via fs.* (read/write/unlink/chmod/chown/readdir) detected"
    );
  }

  // 3) 시크릿/크리덴셜 접근 (process.env, secret, password, credential 등)
  if (/\bprocess\.env\b|secret|password|credential/i.test(lower)) {
    permRisk += 0.3;
    reasons.push(
      "perm: access to process.env / secret / password / credential detected"
    );
  }

  permRisk = clamp01(permRisk);

  return {
    permRisk01: permRisk,
    reasons,
  };
}
