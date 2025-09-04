"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Image from "next/image";

import { Swiper, SwiperSlide } from "swiper/react";
import SwiperCore from "swiper";
import { useVideos } from "../lib/useVideos";

import "swiper/css";
//import "swiper/css/navigation";
import "swiper/css/thumbs";
import "swiper/css/pagination";

import { Fancybox } from "@fancyapps/ui";
import "@fancyapps/ui/dist/fancybox/fancybox.css";

import styles from "../styles/FavoriteVideos.module.css";

SwiperCore.use([]);

interface RecommendedVideosProps {
    sectionTitle?: string;
    favoriteMode?: boolean;
    favoriteVideos?: number[]; // массив id видео
}

export default function RecommendedVideos({
    sectionTitle = "",
    favoriteMode = false,
    favoriteVideos = [],
}: RecommendedVideosProps) {
    const { data: videos = [] } = useVideos();
    const [mainSwiper, setMainSwiper] = useState<SwiperCore | null>(null);
    const [favorites, setFavorites] = useState<number[]>([]);
    const [loadingIds, setLoadingIds] = useState<number[]>([]);
    const router = useRouter();

    useEffect(() => {
        (Fancybox.bind as any)("[data-fancybox]", {
            Toolbar: { display: ["close"] },
            video: { autoStart: true },
        });

        return () => {
            Fancybox.destroy();
        };
    }, []);

    const toggleFavorite = async (videoId: number) => {
        if (loadingIds.includes(videoId)) return;
        setLoadingIds((prev) => [...prev, videoId]);

        try {
            const res = await fetch("/api/favorites", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ videoId }),
                credentials: "include",
            });

            if (res.status === 401) {
                router.push("/sign-in");
                return;
            }

            if (res.ok) {
                const data = await res.json();
                setFavorites(data.favorites || []);
            } else {
                const data = await res.json();
                console.error("Failed to update favorites", data);
            }
        } catch (err) {
            console.error("toggleFavorite error:", err);
        } finally {
            setLoadingIds((prev) => prev.filter((id) => id !== videoId));
        }
    };

    // фильтрация видео в зависимости от режима
    const filteredVideos = videos.filter((video) => {
        if (favoriteMode) {
            if (!favoriteVideos || favoriteVideos.length === 0) return false;
            return favoriteVideos.includes(video.id);
        } else {
            return (video as any)?.rec?.acf?.includes("yes");
        }
    });

    if (filteredVideos.length === 0) return null;

    return (
        <section className={styles.rec}>
            <div className="container">
                <h2 className={styles.redTitle}>{sectionTitle}</h2>
                <Swiper
                    onSwiper={setMainSwiper}
                    spaceBetween={10}
                    loop={true}
                    slidesPerView={"auto"}
                    pagination={{ clickable: true }}
                    className={styles.recSlider}>
                    {filteredVideos.map((video) => {
                        const isFavorite = favorites.includes(video.id);
                        const isLoading = loadingIds.includes(video.id);

                        return (
                            <SwiperSlide key={video.id} className={styles.recSlide}>
                                <div className={styles.recSliderItem}>
                                    <img
                                        src={video.acf.bg}
                                        className={styles.recSliderImg}
                                        alt={video.title.rendered}
                                        width={684}
                                        height={404}
                                    />
                                    <div className={styles.recSliderWrapper}>
                                        <div className={styles.recSliderBox}>
                                            <h3 className={styles.recSliderTitle}>
                                                {video.title.rendered}
                                            </h3>
                                            <p
                                                className={styles.recSliderDesc}
                                                dangerouslySetInnerHTML={{ __html: video.acf.text }}
                                            />
                                        </div>

                                        <a
                                            data-fancybox="gallery"
                                            href={video.acf.video}
                                            className={styles.playButton}></a>
                                    </div>
                                    <div
                                        className={`${styles.btnFavorite} ${
                                            isFavorite ? styles.active : ""
                                        } ${isLoading ? styles.disabled : ""}`}
                                        onClick={() => toggleFavorite(video.id)}>
                                        {isFavorite ? "" : ""}
                                    </div>
                                </div>
                            </SwiperSlide>
                        );
                    })}
                </Swiper>
            </div>
        </section>
    );
}
