import { NextResponse, NextRequest } from "next/server";
import { db } from "@/lib/db";
import bcrypt from "bcryptjs"; // заменяем bcrypt на bcryptjs
import { signToken } from "@/lib/auth";

export async function POST(req: NextRequest) {
    try {
        const { email, password } = await req.json();

        const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
        const user = (rows as any[])[0];
        if (!user) {
            return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
        }

        const token = signToken({ id: user.id, email: user.email });

        const res = new NextResponse(JSON.stringify({ message: "Logged in successfully" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });

        // Устанавливаем cookie с токеном
        res.cookies.set("token", token, { httpOnly: true, path: "/" });

        return res;
    } catch (err) {
        console.error("LOGIN API ERROR:", err);
        return NextResponse.json({ error: "Internal server error" }, { status: 500 });
    }
}
