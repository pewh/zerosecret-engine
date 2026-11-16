const mysql = require("mysql2/promise");

const env = process.env;

async function main() {
  const connection = await mysql.createConnection({
    host: env.ZS_ADMIN_HOST,
    port: Number(env.ZS_ADMIN_PORT),
    user: "root",
    password: env.ZS_ADMIN_PASSWORD,
  });
  const [rows] = await connection.query(env.ZS_ADMIN_SQL);
  const first = Array.isArray(rows) && rows.length > 0 ? Object.values(rows[0])[0] : "";
  console.log(String(first));
  await connection.end();
}

main().catch((error) => {
  console.error(`admin: ${error.message}`);
  process.exit(1);
});
