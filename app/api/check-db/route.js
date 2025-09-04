import { checkDBConnection } from "@/lib/db";

export async function GET() {
    const ok = await checkDBConnection();
    return Response.json({ connected: ok });
}
