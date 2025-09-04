import { useQuery } from "@tanstack/react-query";

export interface VideoItem {
    id: number;
    title: { rendered: string };
    acf: {
        thumb: string;
        tab: string;
        cat: string;
        text: string;
        video: string;
        bg: string;
    };
    thumbnail: string;
}

export function useVideos() {
    return useQuery<VideoItem[]>({
        queryKey: ["videos"],
        queryFn: async () => {
            const baseUrl = process.env.NEXT_PUBLIC_SITE_URL;

            const res = await fetch(
                `${baseUrl}/wp-json/wp/v2/video?_fields=id,title,acf,slug,featured_media&_embed`,
            );
            if (!res.ok) throw new Error("Failed to fetch videos");

            const data = await res.json();
            //console.log("VIDEOS API:", data);

            // Используем _embedded для featured_media
            const videos: VideoItem[] = data.map((video: any) => ({
                id: video.id,
                title: video.title,
                acf: video.acf,
                thumbnail: video._embedded?.["wp:featuredmedia"]?.[0]?.source_url || "",
            }));

            return videos;
        },
        staleTime: 60_000,
    });
}
