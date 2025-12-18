export type PgQueryResult<Row> = {
  rows: Row[];
  rowCount: number | null;
};

export type PgClient = {
  query<Row = unknown>(text: string, values?: readonly unknown[]): Promise<PgQueryResult<Row>>;
  release(): void;
};

/**
 * Minimal structural type for `pg.Pool` (so consumers don't *need* pg's TS types).
 */
export type PgPool = {
  query<Row = unknown>(text: string, values?: readonly unknown[]): Promise<PgQueryResult<Row>>;
  connect(): Promise<PgClient>;
};
