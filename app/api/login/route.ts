import { NextResponse, NextRequest } from "next/server";
import { db } from "@/lib/db";
import bcrypt from "bcryptjs";
import { signToken } from "@/lib/auth";

export async function POST(req: NextRequest) {
    try {
        const { email, password } = await req.json();
        console.log("LOGIN ATTEMPT:", { email });

        const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
        console.log("DB QUERY RESULT:", rows);

        const user = (rows as any[])[0];
        if (!user) {
            console.log("USER NOT FOUND:", email);
            return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        console.log("PASSWORD MATCH:", isMatch);

        if (!isMatch) {
            console.log("INVALID PASSWORD FOR:", email);
            return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
        }

        const token = signToken({ id: user.id, email: user.email });
        console.log("TOKEN GENERATED:", token);

        const res = new NextResponse(JSON.stringify({ message: "Logged in successfully" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });

        res.cookies.set("token", token, { httpOnly: true, path: "/" });
        console.log("COOKIE SET SUCCESSFULLY");

        return res;
    } catch (err) {
        console.error("LOGIN API ERROR:", err);
        return NextResponse.json({ error: "Internal server error" }, { status: 500 });
    }
}
