const { Client } = require("pg");

const env = process.env;
const table = env.ZS_CLIENT_TABLE;
const readOnly = env.ZS_CLIENT_ACCESS === "read_only";
let failed = false;

async function attempt(client, sql) {
  try {
    const result = await client.query(sql);
    return { ok: true, rows: result.rows };
  } catch (error) {
    return { ok: false, code: error.code, message: error.message };
  }
}

function writeStep(step, outcome) {
  if (readOnly && !outcome.ok && /read[-_ ]only/i.test(outcome.message)) {
    console.log(`${step}: refused ${outcome.code} ${outcome.message}`);
  } else if (!readOnly && outcome.ok) {
    console.log(`${step}: ok`);
  } else {
    console.log(`${step}: FAIL ${outcome.ok ? "succeeded" : outcome.message}`);
    failed = true;
  }
}

function readStep(step, outcome, expected) {
  const rows = outcome.ok ? outcome.rows[0].count : outcome.message;
  if (outcome.ok && rows === String(expected)) {
    console.log(`${step}: ok rows=${rows}`);
  } else {
    console.log(`${step}: FAIL rows=${rows}`);
    failed = true;
  }
}

async function main() {
  const client = new Client({
    host: env.ZS_CLIENT_HOST,
    port: Number(env.ZS_CLIENT_PORT),
    user: env.ZS_CLIENT_USER,
    database: env.ZS_CLIENT_DB,
    ssl: false,
  });
  await client.connect();
  readStep("read", await attempt(client, `SELECT count(*) FROM ${table}`), 1);
  writeStep("write", await attempt(client, `INSERT INTO ${table} VALUES (2)`));
  writeStep("switch-off", await attempt(client, "SET default_transaction_read_only = off"));
  writeStep("write-after-switch-off", await attempt(client, `INSERT INTO ${table} VALUES (3)`));
  readStep("read-after", await attempt(client, `SELECT count(*) FROM ${table}`), readOnly ? 1 : 3);
  await client.end();
}

main().catch((error) => {
  console.log(`error: FAIL ${error.message}`);
  process.exit(1);
}).then(() => process.exit(failed ? 1 : 0));
