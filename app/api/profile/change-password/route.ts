import { NextResponse, NextRequest } from "next/server";
import { db } from "@/lib/db";
import bcrypt from "bcryptjs"; // лучше bcryptjs для TS
import { verifyToken } from "@/lib/auth";

export async function POST(req: NextRequest) {
    try {
        const token = req.cookies.get("token")?.value;
        if (!token) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

        const payload = verifyToken(token);
        if (!payload) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

        const { currentPassword, newPassword } = await req.json();
        if (!currentPassword || !newPassword)
            return NextResponse.json({ error: "Fields required" }, { status: 400 });

        const [rows] = await db.query("SELECT password_hash FROM users WHERE id = ?", [
            (payload as any).id,
        ]);
        const user = (rows as any[])[0];

        const match = await bcrypt.compare(currentPassword, user.password_hash);
        if (!match)
            return NextResponse.json({ error: "Current password incorrect" }, { status: 400 });

        const hash = await bcrypt.hash(newPassword, 10);
        await db.query("UPDATE users SET password_hash = ? WHERE id = ?", [
            hash,
            (payload as any).id,
        ]);

        return NextResponse.json({ message: "Password changed" });
    } catch (err) {
        return NextResponse.json({ error: "Internal server error" }, { status: 500 });
    }
}
