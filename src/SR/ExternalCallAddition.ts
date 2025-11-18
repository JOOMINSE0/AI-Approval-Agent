// src/SR/ExternalCallAddition.ts

export type ExternalCallMetrics = {
  externalCalls: number;   // HTTP·DB 등 외부 호출 개수
  ioCalls: number;         // fs.* 등 파일 I/O 호출 개수
  reasons: string[];       // 로그용 설명 메시지
};

/**
 * External Call Addition
 *  - fetch, axios, http.*, DB 클라이언트, fs.* 등 외부/파일 I/O 호출 개수를 정규식으로 스캔
 */
export function analyzeExternalCallAddition(code: string): ExternalCallMetrics {
  const reasons: string[] = [];

  // 네트워크/DB 등 외부 호출
  const externalCalls =
    (code.match(
      /\b(fetch|axios|request|http\.|https\.|jdbc|mongo|redis|sequelize|prisma)\b/gi
    ) || []).length;

  // 파일 시스템 I/O 호출
  const ioCalls =
    (code.match(
      /\bfs\.(read|write|append|unlink|readdir|chmod|chown)|open\(|readFileSync|writeFileSync\b/gi
    ) || []).length;

  if (externalCalls > 0) {
    reasons.push(
      `Detected ${externalCalls} external network/DB calls (fetch/axios/http*/DB client).`
    );
  }
  if (ioCalls > 0) {
    reasons.push(
      `Detected ${ioCalls} file-system I/O calls (fs.*, readFileSync, writeFileSync, etc.).`
    );
  }

  return { externalCalls, ioCalls, reasons };
}
