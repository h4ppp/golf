import { useQuery } from "@tanstack/react-query";

export interface EventItem {
    id: number;
    title: { rendered: string };
    slug: string;
}

export function useEvents() {
    return useQuery<EventItem[]>({
        queryKey: ["events"],
        queryFn: async () => {
            const baseUrl = process.env.NEXT_PUBLIC_SITE_URL;

            const res = await fetch(
                `${baseUrl}/wp-json/wp/v2/events?_fields=id,title,acf,slug,featured_media&_embed`,
            );
            if (!res.ok) throw new Error("Failed to fetch events");

            const data = await res.json();

            const events: EventItem[] = data.map((event: any) => ({
                id: event.id,
                title: event.title,
                date: event.acf.date,
                img: event.acf.img,
                text: event.acf.text,
            }));

            return events;
        },
        staleTime: 60_000,
    });
}
