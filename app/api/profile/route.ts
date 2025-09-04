import { NextResponse, NextRequest } from "next/server";
import { verifyToken } from "@/lib/auth";
import { getUserByEmail } from "@/lib/db";

export async function GET(req: NextRequest) {
    try {
        const token = req.cookies.get("token")?.value;
        if (!token) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        const payload = verifyToken(token);
        if (!payload) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        const user = await getUserByEmail((payload as any).email);
        if (!user) {
            return NextResponse.json({ error: "User not found" }, { status: 404 });
        }

        let favoriteVideos: any = null;
        try {
            favoriteVideos = user.favorite_videos ? JSON.parse(user.favorite_videos) : ["90"];
        } catch (e) {
            favoriteVideos = null;
        }

        return NextResponse.json({
            email: user.email,
            first_name: user.first_name || "",
            second_name: user.second_name || "",
            favorite_videos: favoriteVideos,
        });
    } catch (err) {
        console.error("PROFILE API ERROR:", err);
        return NextResponse.json({ error: "Internal server error" }, { status: 500 });
    }
}
