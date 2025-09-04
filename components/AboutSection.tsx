"use client";

import styles from "../styles/AboutSection.module.css";
import Image from "next/image";
import { usePosts } from "../lib/usePosts";

export default function FAQSection() {
    const { data } = usePosts();
    const homePage = data?.find((page: any) => page.slug === "home");
    const aboutTitle = homePage?.acf?.abouttitle;
    const aboutText = homePage?.acf?.abouttext;
    const aboutList = homePage?.acf?.aboutlist || [];

    return (
        <section className={styles.about} id="about">
            <Image
                src="/img/about.png"
                className={styles.img}
                alt="About Us"
                width={1793}
                height={983}
            />
            <div className="container index">
                <div className={styles.wrapper}>
                    <h2 className={styles.title}>{aboutTitle}</h2>
                    <div className={styles.list}>
                        {aboutList.map((item: any, index: number) => (
                            <div className={styles.item} key={index}>
                                <Image
                                    src={item.img}
                                    className={styles.icon}
                                    alt="about us icon"
                                    width={80}
                                    height={80}
                                />
                                <div
                                    className={styles.itemText}
                                    dangerouslySetInnerHTML={{ __html: item.text }}></div>
                            </div>
                        ))}
                    </div>
                    <div
                        className={styles.text}
                        dangerouslySetInnerHTML={{ __html: aboutText }}></div>
                </div>
            </div>
        </section>
    );
}
