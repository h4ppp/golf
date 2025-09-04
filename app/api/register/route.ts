import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import bcrypt from "bcrypt";

export async function POST(req: Request) {
    try {
        const body = await req.json();
        const { email, first_name, second_name, country, password, confirmPassword } = body;

        if (!email || !password || !confirmPassword) {
            return NextResponse.json({ error: "Required fields missing" }, { status: 400 });
        }

        if (password !== confirmPassword) {
            return NextResponse.json({ error: "Passwords do not match" }, { status: 400 });
        }

        const [rows] = await db.query("SELECT id FROM users WHERE email = ?", [email]);
        if ((rows as any[]).length > 0) {
            return NextResponse.json({ error: "Email already exists" }, { status: 400 });
        }

        const hash = await bcrypt.hash(password, 10);
        await db.query(
            "INSERT INTO users (email, first_name, second_name, country, password_hash) VALUES (?, ?, ?, ?, ?)",
            [email, first_name, second_name, country, hash],
        );

        return NextResponse.json({ message: "User registered successfully!" });
    } catch (err) {
        return NextResponse.json({ error: "Internal server error" }, { status: 500 });
    }
}
