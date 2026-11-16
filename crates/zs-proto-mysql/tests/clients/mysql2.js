const mysql = require("mysql2/promise");

const env = process.env;
const table = env.ZS_CLIENT_TABLE;
const readOnly = env.ZS_CLIENT_ACCESS === "read_only";
const REFUSED = "zs: refused, read-only resource";
let failed = false;

async function attempt(run) {
  try {
    const [rows] = await run();
    return { ok: true, rows };
  } catch (error) {
    return {
      ok: false,
      errno: error.errno,
      state: error.sqlState,
      message: error.sqlMessage || error.message,
    };
  }
}

function writeStep(step, outcome, accepts) {
  if (readOnly && !outcome.ok && accepts(outcome)) {
    console.log(`${step}: refused ${outcome.errno} ${outcome.state} ${outcome.message}`);
  } else if (!readOnly && outcome.ok) {
    console.log(`${step}: ok`);
  } else {
    console.log(`${step}: FAIL ${outcome.ok ? "succeeded" : `${outcome.errno} ${outcome.message}`}`);
    failed = true;
  }
}

function readStep(step, outcome, expected) {
  const rows = outcome.ok ? Number(outcome.rows[0].n) : outcome.message;
  if (outcome.ok && rows === expected) {
    console.log(`${step}: ok rows=${rows}`);
  } else {
    console.log(`${step}: FAIL rows=${rows}`);
    failed = true;
  }
}

const readOnlyError = (o) => o.errno === 1792 && /read only/i.test(o.message);
const refusedByAgent = (o) => o.errno === 1792 && o.message === REFUSED;
const anyRefusal = () => true;

async function main() {
  const connection = await mysql.createConnection({
    host: env.ZS_CLIENT_HOST,
    port: Number(env.ZS_CLIENT_PORT),
    user: env.ZS_CLIENT_USER,
    database: env.ZS_CLIENT_DB,
  });
  const count = `SELECT count(*) AS n FROM ${table}`;
  const insert = (id) => `INSERT INTO ${table} VALUES (${id})`;
  const switchOff = "SET SESSION TRANSACTION READ WRITE";

  readStep("read", await attempt(() => connection.query(count)), 1);
  writeStep("write", await attempt(() => connection.query(insert(2))), readOnlyError);
  writeStep("switch-off", await attempt(() => connection.query(switchOff)), refusedByAgent);
  writeStep("prepared-switch-off", await attempt(() => connection.execute(switchOff)), anyRefusal);
  writeStep("write-after-switch-off", await attempt(() => connection.query(insert(3))), readOnlyError);
  readStep("prepared-read", await attempt(() => connection.execute(count)), readOnly ? 1 : 3);
  writeStep(
    "prepared-write",
    await attempt(() => connection.execute(`INSERT INTO ${table} VALUES (?)`, [4])),
    readOnlyError,
  );
  readStep("read-after", await attempt(() => connection.query(count)), readOnly ? 1 : 4);
  await connection.end();
}

main()
  .catch((error) => {
    console.log(`error: FAIL ${error.message}`);
    failed = true;
  })
  .then(() => process.exit(failed ? 1 : 0));
