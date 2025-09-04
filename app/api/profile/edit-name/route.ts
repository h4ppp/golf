import { NextResponse, NextRequest } from "next/server";
import { db } from "@/lib/db";
import { verifyToken } from "@/lib/auth";

export async function POST(req: NextRequest) {
    try {
        const token = req.cookies.get("token")?.value;
        if (!token) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

        const payload = verifyToken(token);
        if (!payload) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

        const { first_name, second_name } = await req.json();
        if (!first_name || !second_name)
            return NextResponse.json({ error: "Fields required" }, { status: 400 });

        await db.query("UPDATE users SET first_name = ?, second_name = ? WHERE id = ?", [
            first_name,
            second_name,
            (payload as any).id,
        ]);

        return NextResponse.json({ message: "Name updated" });
    } catch (err) {
        return NextResponse.json({ error: "Internal server error" }, { status: 500 });
    }
}
