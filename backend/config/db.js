import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || "sdvitsystem",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  decimalNumbers: true,
  // Return DATE columns as 'YYYY-MM-DD' strings so they never shift by a day
  // when converted to JSON in a non-UTC timezone.
  dateStrings: ["DATE"]
});

export default pool;
