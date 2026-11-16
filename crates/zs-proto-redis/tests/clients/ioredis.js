const Redis = require("ioredis");

const env = process.env;
const prefix = env.ZS_CLIENT_TABLE;
const readOnly = env.ZS_CLIENT_ACCESS === "read_only";
const key = (name) => `${prefix}:${name}`;
let failed = false;

async function attempt(run) {
  try {
    return { ok: true, value: await run() };
  } catch (error) {
    return { ok: false, message: error.message };
  }
}

function writeStep(step, outcome, refusal) {
  if (readOnly && !outcome.ok && refusal.test(outcome.message)) {
    console.log(`${step}: refused ${outcome.message}`);
  } else if (!readOnly && outcome.ok) {
    console.log(`${step}: ok`);
  } else {
    console.log(`${step}: FAIL ${outcome.ok ? "succeeded" : outcome.message}`);
    failed = true;
  }
}

function readStep(step, outcome, expected) {
  if (outcome.ok && outcome.value === expected) {
    console.log(`${step}: ok value=${outcome.value}`);
  } else {
    console.log(`${step}: FAIL value=${outcome.ok ? outcome.value : outcome.message}`);
    failed = true;
  }
}

const noperm = /^NOPERM read-only resource$/;

async function main() {
  const errors = [];
  const redis = new Redis({
    host: env.ZS_CLIENT_HOST,
    port: Number(env.ZS_CLIENT_PORT),
    maxRetriesPerRequest: 1,
    retryStrategy: () => null,
    ...(env.ZS_CLIENT_OPTIONS ? JSON.parse(env.ZS_CLIENT_OPTIONS) : {}),
  });
  redis.on("error", (error) => errors.push(error.message));

  readStep("read", await attempt(() => redis.get(key("k"))), "v1");
  writeStep("set", await attempt(() => redis.set(key("new"), "x", "EX", 300)), noperm);
  writeStep("incr", await attempt(() => redis.incr(key("ctr"))), noperm);
  writeStep("lpush", await attempt(() => redis.lpush(key("list"), "a")), noperm);
  const pipeline = await attempt(async () => {
    const results = await redis.pipeline().get(key("k")).set(key("pipe"), "x", "EX", 300).exec();
    if (results[0][0] || results[0][1] !== "v1") {
      throw new Error(`pipeline read ${results[0][0] ? results[0][0].message : results[0][1]}`);
    }
    if (results[1][0]) throw results[1][0];
  });
  writeStep("pipeline-write", pipeline, noperm);
  const multi = await attempt(() => redis.multi().set(key("multi"), "x", "EX", 300).exec());
  writeStep("multi-write", multi, /^(NOPERM read-only resource|EXECABORT .*)$/);
  writeStep("del", await attempt(() => redis.del(key("k"))), noperm);
  readStep("read-after", await attempt(() => redis.get(key("k"))), readOnly ? "v1" : null);

  const info = await attempt(() => redis.info());
  console.log(`fact info: ${info.ok ? "ok" : info.message}`);
  const script = await attempt(() => redis.eval("return 1", 0));
  console.log(`fact eval: ${script.ok ? "ok" : script.message}`);
  console.log(`fact connection-errors: ${errors.length === 0 ? "none" : errors.join(" | ")}`);
  redis.disconnect();
}

main()
  .catch((error) => {
    console.log(`error: FAIL ${error.message}`);
    failed = true;
  })
  .then(() => process.exit(failed ? 1 : 0));
