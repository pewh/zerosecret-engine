const { MongoClient } = require("mongodb");

const env = process.env;

async function main() {
  const client = new MongoClient(`mongodb://${env.ZS_ADMIN_HOST}:${env.ZS_ADMIN_PORT}/`, {
    auth: { username: env.ZS_ADMIN_USER, password: env.ZS_ADMIN_PASSWORD },
    authSource: env.ZS_ADMIN_DB,
    directConnection: true,
    tls: false,
    serverSelectionTimeoutMS: 15000,
  });
  await client.connect();
  const collection = client.db(env.ZS_ADMIN_DB).collection(env.ZS_ADMIN_COLLECTION);
  switch (env.ZS_ADMIN_OP) {
    case "seed":
      await collection.drop().catch(() => {});
      await collection.insertOne({ _id: 1 });
      console.log("seeded");
      break;
    case "count":
      console.log(String(await collection.countDocuments({})));
      break;
    case "touched":
      console.log(String(await collection.countDocuments({ touched: true })));
      break;
    case "drop":
      await collection.drop().catch(() => {});
      console.log("dropped");
      break;
    default:
      throw new Error("unknown operation");
  }
  await client.close();
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(`admin: ${error.message}`);
    process.exit(1);
  });
