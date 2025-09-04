import mysql from "mysql2/promise";

export const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
});

export async function checkDBConnection() {
    try {
        const connection = await db.getConnection();
        connection.release();
        return true;
    } catch (error) {
        console.error("Database connection failed:", error);
        return false;
    }
}

export async function getUserByEmail(email) {
    const [rows] = await db.query(
        "SELECT email, first_name, second_name FROM users WHERE email = ? LIMIT 1",
        [email],
    );
    return rows[0] || null;
}
