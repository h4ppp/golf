import { useQuery } from "@tanstack/react-query";

export function usePosts() {
    return useQuery({
        queryKey: ["posts"],
        queryFn: async () => {
            const baseUrl = process.env.NEXT_PUBLIC_SITE_URL;
            const res = await fetch(`${baseUrl}/wp-json/wp/v2/pages?_fields=id,title,acf,slug`);
            if (!res.ok) throw new Error("Failed to fetch posts");
            return res.json();
        },
        staleTime: 60_000,
    });
}
