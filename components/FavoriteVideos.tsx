"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
//import Cookies from "js-cookie";
import Image from "next/image";

import { Swiper, SwiperSlide } from "swiper/react";
import SwiperCore from "swiper";
import { useVideos } from "../lib/useVideos";

import "swiper/css";
//import "swiper/css/thumbs";

import { Fancybox } from "@fancyapps/ui";
import "@fancyapps/ui/dist/fancybox/fancybox.css";

import styles from "../styles/FavoriteVideos.module.css";

SwiperCore.use([]);

export default function FavoriteVideos() {
    const { data: videos = [] } = useVideos();
    const [thumbsSwiper, setThumbsSwiper] = useState<SwiperCore | null>(null);
    const [mainSwiper, setMainSwiper] = useState<SwiperCore | null>(null);
    const [favorites, setFavorites] = useState<number[]>([]);
    const [loadingIds, setLoadingIds] = useState<number[]>([]); // для блокировки кнопок
    const [activeIndex, setActiveIndex] = useState(0);
    const router = useRouter();

    useEffect(() => {
        (Fancybox.bind as any)("[data-fancybox]", {
            toolbar: false,
            video: { autoStart: true },
        });

        return () => {
            Fancybox.destroy();
        };
    }, []);

    // Получаем фавориты пользователя
    //useEffect(() => {
    //    const fetchFavorites = async () => {
    //        const token = Cookies.get("token");
    //        if (!token) return;

    //        try {
    //            const res = await fetch("/api/favorites", { credentials: "include" });
    //            if (res.ok) {
    //                const data = await res.json();
    //                setFavorites(data.favorites || []);
    //            }
    //        } catch (err) {
    //            console.error("Failed to fetch favorites", err);
    //        }
    //    };
    //    fetchFavorites();
    //}, []);

    const toggleFavorite = async (videoId: number) => {
        if (loadingIds.includes(videoId)) return; // блокировка кнопки
        setLoadingIds((prev) => [...prev, videoId]);
        console.log(videoId);

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

    return (
        <section className={styles.section}>
            <div className="container">
                <div className={styles.flex}>
                    <h2 className={styles.title}>Videos</h2>
                    <Image
                        src="/img/video-title.png"
                        className={styles.desktop}
                        alt="Videos"
                        width={983}
                        height={151}
                    />
                    <Image
                        src="/img/video-mobile.png"
                        className={styles.mobile}
                        alt="Videos"
                        width={346}
                        height={99}
                    />
                </div>
                <Swiper
                    onSwiper={setThumbsSwiper}
                    spaceBetween={6}
                    slidesPerView={"auto"}
                    loop={true}
                    className={styles.thumbsSlider}>
                    {videos.map((video, index) => (
                        <SwiperSlide
                            key={video.id}
                            className={`${styles.thumbSlide} ${
                                index === activeIndex ? "active" : ""
                            }`}
                            onClick={() => mainSwiper?.slideToLoop(index)}>
                            <div className={styles.thumbItem}>
                                <img
                                    src={video.acf.thumb}
                                    className={styles.icon}
                                    alt={video.title.rendered}
                                    width={339}
                                    height={185}
                                />
                                <p>{video.acf.tab}</p>
                            </div>
                        </SwiperSlide>
                    ))}
                </Swiper>

                <Swiper
                    onSwiper={setMainSwiper}
                    spaceBetween={10}
                    loop={true}
                    navigation
                    thumbs={thumbsSwiper ? { swiper: thumbsSwiper } : undefined}
                    className={styles.mainSlider}
                    onSlideChange={(swiper) => setActiveIndex(swiper.realIndex)}>
                    {videos.map((video) => {
                        const isFavorite = favorites.includes(video.id);
                        const isLoading = loadingIds.includes(video.id);

                        return (
                            <SwiperSlide key={video.id} className={styles.mainSlide}>
                                <div className={styles.mainSlideItem}>
                                    <img
                                        src={video.acf.bg}
                                        className={styles.mainItemImg}
                                        alt={video.title.rendered}
                                        width={1721}
                                        height={703}
                                    />
                                    <div className={styles.mainItemWrapper}>
                                        <div className={styles.mainItemBox}>
                                            <p className={styles.category}>{video.acf.cat}</p>
                                            <h3 className={styles.videoTitle}>
                                                {video.title.rendered}
                                            </h3>
                                            <p
                                                className={styles.description}
                                                dangerouslySetInnerHTML={{ __html: video.acf.text }}
                                            />

                                            <a
                                                data-fancybox="gallery"
                                                href={video.acf.video}
                                                className={styles.playButton}></a>
                                        </div>
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
