const { MongoClient } = require("mongodb");

const env = process.env;
const readOnly = env.ZS_CLIENT_ACCESS === "read_only";
const REFUSED = "zs: refused, read-only resource";
let failed = false;

async function attempt(run) {
  try {
    return { ok: true, value: await run() };
  } catch (error) {
    return { ok: false, code: error.code, codeName: error.codeName, message: error.message };
  }
}

function writeStep(step, outcome) {
  if (readOnly && !outcome.ok && outcome.code === 13 && outcome.message === REFUSED) {
    console.log(`${step}: refused ${outcome.code} ${outcome.codeName} ${outcome.message}`);
  } else if (!readOnly && outcome.ok) {
    console.log(`${step}: ok`);
  } else {
    console.log(`${step}: FAIL ${outcome.ok ? "succeeded" : `${outcome.code} ${outcome.message}`}`);
    failed = true;
  }
}

function readStep(step, outcome, expected) {
  if (outcome.ok && outcome.value === expected) {
    console.log(`${step}: ok rows=${outcome.value}`);
  } else {
    console.log(`${step}: FAIL rows=${outcome.ok ? outcome.value : outcome.message}`);
    failed = true;
  }
}

async function main() {
  const client = new MongoClient(
    `mongodb://${env.ZS_CLIENT_HOST}:${env.ZS_CLIENT_PORT}/${env.ZS_CLIENT_DB}`,
    { serverSelectionTimeoutMS: 15000, tls: false },
  );
  await client.connect();
  const collection = client.db(env.ZS_CLIENT_DB).collection(env.ZS_CLIENT_TABLE);
  const found = async () => (await collection.find({}).toArray()).length;

  readStep("read", await attempt(found), 1);
  readStep("read-count", await attempt(() => collection.countDocuments({})), 1);
  writeStep("insert", await attempt(() => collection.insertOne({ _id: 2 })));
  writeStep("update", await attempt(() => collection.updateOne({ _id: 1 }, { $set: { touched: true } })));
  writeStep("insert-again", await attempt(() => collection.insertOne({ _id: 3 })));
  writeStep("delete", await attempt(() => collection.deleteOne({ _id: 3 })));
  writeStep("create-index", await attempt(() => collection.createIndex({ marker: 1 })));
  readStep("read-after", await attempt(found), readOnly ? 1 : 2);

  const scratch = client.db(env.ZS_CLIENT_DB).collection(`${env.ZS_CLIENT_TABLE}_absent`);
  let stage = "start";
  const session = client.startSession();
  const transaction = await attempt(async () => {
    session.startTransaction();
    stage = "find-in-transaction";
    await scratch.find({}, { session }).toArray();
    stage = "commit";
    await session.commitTransaction();
  });
  console.log(
    `fact transaction: ${transaction.ok ? "ok" : `${stage} ${transaction.code} ${transaction.codeName} ${transaction.message}`}`,
  );
  await session.endSession().catch(() => {});
  await client.close();
}

main()
  .catch((error) => {
    console.log(`error: FAIL ${error.message}`);
    failed = true;
  })
  .then(() => process.exit(failed ? 1 : 0));
