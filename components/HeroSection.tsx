"use client";

import styles from "../styles/HeroSection.module.css";
import Image from "next/image";
import { usePosts } from "../lib/usePosts";

export default function FAQSection() {
    const { data } = usePosts();
    const homePage = data?.find((page: any) => page.slug === "home");
    const mainTitle = homePage?.acf?.maintitle;
    const mainVideo = homePage?.acf?.mainvideo;
    const mainList = homePage?.acf?.mainlist || [];

    const socialLinks = [
        { href: homePage?.acf?.instagram, icon: "/img/main-soc-1.svg", alt: "instagram" },
        { href: homePage?.acf?.x, icon: "/img/main-soc-2.svg", alt: "x" },
        { href: homePage?.acf?.tiktok, icon: "/img/main-soc-3.svg", alt: "tiktok" },
        { href: homePage?.acf?.youtube, icon: "/img/main-soc-4.svg", alt: "youtube" },
    ];

    return (
        <section className={styles.section}>
            <div className="container index">
                <div className={styles.wrapper}>
                    <h1
                        className={styles.title}
                        dangerouslySetInnerHTML={{ __html: mainTitle }}></h1>

                    <div className={styles.list}>
                        <div className={styles.block}>
                            <a
                                data-fancybox="gallery"
                                href={mainVideo}
                                className={`${styles.playButton} btn`}>
                                <span>WATCH NOW</span>
                                <Image
                                    src="/img/play-white.svg"
                                    alt="play"
                                    width={50}
                                    height={50}
                                />
                            </a>
                            <div className={styles.soc}>
                                {socialLinks.map(
                                    (soc, i) =>
                                        soc.href && (
                                            <a
                                                key={i}
                                                href={soc.href}
                                                target="_blank"
                                                className={styles.socItem}>
                                                <Image
                                                    src={soc.icon}
                                                    alt={soc.alt}
                                                    width={24}
                                                    height={24}
                                                />
                                            </a>
                                        ),
                                )}
                            </div>
                        </div>
                        <div className={styles.list}></div>
                        {mainList.map((item: any, index: number) => (
                            <div className={styles.item} key={index}>
                                <div className={styles.images}>
                                    {item.child_repeater.map((img: any, index: number) => (
                                        <img
                                            key={index}
                                            src={img.img}
                                            className={styles.icon}
                                            alt=""
                                            width={140}
                                            height={140}
                                        />
                                    ))}
                                </div>
                                <div className={styles.itemTitle}>{item.title}</div>
                                <div
                                    className={styles.itemText}
                                    dangerouslySetInnerHTML={{ __html: item.text }}></div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </section>
    );
}
