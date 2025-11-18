// src/SchemaChange.ts
// 스키마 변경 여부를 감지하는 전용 모듈
//  - 지금은 키워드 기반이지만, 나중에 ORM/SQL AST 패턴으로 확장 가능

export type SchemaChangeSignal = {
  schemaChanged: boolean;
  reason: string;
};

export function detectSchemaChange(code: string): SchemaChangeSignal {
  const lower = code.toLowerCase();

  // 1) 순수 SQL DDL 키워드 (기존 정규식 그대로)
  const ddlRegex = /\b(alter\s+table|create\s+table|drop\s+table|migration)\b/i;
  const ddlHit = ddlRegex.test(code);

  // 2) ORM 마이그레이션/스키마 관련 흔한 패턴 (확장 여지)
  const typeOrmHint =
    /\b@entity\b|\b@Column\b|\bPrimaryGeneratedColumn\b|\bMigrationInterface\b/i.test(code);
  const prismaHint =
    /\bmodel\b[\s\S]+?\{[\s\S]*?\}/i.test(code) && /prisma/i.test(code);
  const sequelizeHint =
    /\bsequelize\.define\b|\bqueryInterface\.createTable\b|\bqueryInterface\.dropTable\b/i.test(code);

  const schemaChanged = ddlHit || typeOrmHint || prismaHint || sequelizeHint;

  let reason = "no schema change detected";
  if (schemaChanged) {
    const reasons: string[] = [];
    if (ddlHit) reasons.push("SQL DDL keyword (ALTER/CREATE/DROP TABLE/MIGRATION) detected");
    if (typeOrmHint) reasons.push("TypeORM entity/migration pattern detected");
    if (prismaHint) reasons.push("Prisma schema-like model definition detected");
    if (sequelizeHint) reasons.push("Sequelize migration/queryInterface pattern detected");
    reason = reasons.join("; ");
  }

  return { schemaChanged, reason };
}
