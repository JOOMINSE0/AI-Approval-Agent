// src/CoreModuleModified.ts
// "Core Module Modified" 신호만 담당하는 작은 유틸 모듈

/**
 * 코어 모듈 파일인지 여부를 판별한다.
 *
 * - filename 경로에 /core/, /service/, /domain/ 이 포함되면 코어 모듈로 간주
 * - 윈도우 경로(\)도 / 로 통일해서 검사
 */
export function isCoreModuleModified(
  filename: string | null | undefined
): boolean {
  if (!filename) return false;

  // 윈도우 경로 -> POSIX 스타일로 정규화
  const norm = filename.replace(/\\/g, "/");

  // 기존에 쓰던 규칙 그대로 유지
  return /(\/|^)(core|service|domain)\//i.test(norm);
}
