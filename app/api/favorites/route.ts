import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { verifyToken } from "@/lib/auth";

// Безопасный парсинг JSON или CSV в массив чисел
const safeParse = (value: string | null): number[] => {
    if (!value) return [];
    try {
        const parsed = JSON.parse(value);
        if (Array.isArray(parsed)) return parsed.map((n) => Number(n)).filter((n) => !isNaN(n));
    } catch {
        return value
            .toString()
            .split(",")
            .map((n) => Number(n))
            .filter((n) => !isNaN(n));
    }
    return [];
};

export async function POST(req: NextRequest) {
    try {
        const token = req.cookies.get("token")?.value;
        if (!token) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

        const user = verifyToken(token);
        if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

        const userId = (user as any).id;
        const { videoId } = await req.json();

        if (!videoId) return NextResponse.json({ error: "Video ID required" }, { status: 400 });

        const [rows]: any = await db.query("SELECT favorite_videos FROM users WHERE id = ?", [
            userId,
        ]);

        let favorites = safeParse(rows[0]?.favorite_videos || null);

        const idNum = Number(videoId);
        if (isNaN(idNum)) return NextResponse.json({ error: "Invalid video ID" }, { status: 400 });

        // toggle logic: если уже есть → удаляем, иначе добавляем
        if (favorites.includes(idNum)) {
            favorites = favorites.filter((id) => id !== idNum);
        } else {
            favorites.push(idNum);
        }

        await db.query("UPDATE users SET favorite_videos = ? WHERE id = ?", [
            JSON.stringify(favorites),
            userId,
        ]);

        return NextResponse.json({ favorites });
    } catch (err: any) {
        console.error("POST /favorites error:", err);
        return NextResponse.json(
            { error: err.message || "Internal server error" },
            { status: 500 },
        );
    }
}

export async function GET(req: NextRequest) {
    try {
        const token = req.cookies.get("token")?.value;
        if (!token) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

        const user = verifyToken(token);
        if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

        const userId = (user as any).id;

        const [rows]: any = await db.query("SELECT favorite_videos FROM users WHERE id = ?", [
            userId,
        ]);

        const favorites = safeParse(rows[0]?.favorite_videos || null);

        return NextResponse.json({ favorites });
    } catch (err: any) {
        console.error("GET /favorites error:", err);
        return NextResponse.json(
            { error: err.message || "Internal server error" },
            { status: 500 },
        );
    }
}
