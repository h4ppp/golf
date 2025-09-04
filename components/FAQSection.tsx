"use client";

import { useState } from "react";
import styles from "../styles/FAQSection.module.css";
import Image from "next/image";
import { usePosts } from "../lib/usePosts";

export default function FAQSection() {
    const { data } = usePosts();
    const homePage = data?.find((page: any) => page.slug === "home");
    const acfTitle = homePage?.acf?.faqtitle;
    const faqList = homePage?.acf?.faqlist || [];

    const [openIndex, setOpenIndex] = useState<number | null>(null);

    const toggleOpen = (index: number) => {
        setOpenIndex(openIndex === index ? null : index);
    };

    return (
        <section className={styles.faq} id="faq">
            <div className="container">
                <div className={styles.wrapper}>
                    <div className={styles.top}>
                        <h2
                            className={styles.title}
                            dangerouslySetInnerHTML={{ __html: acfTitle }}></h2>
                        <Image
                            src="/img/faq.png"
                            className={styles.img}
                            alt="FAQ"
                            width={797}
                            height={230}
                        />
                        <Image
                            src="/img/faq-mobile.png"
                            className={styles.mobile}
                            alt="FAQ"
                            width={690}
                            height={262}
                        />
                    </div>
                    <div className={styles.list}>
                        <div className={styles.list}>
                            {faqList.map((item: any, index: number) => (
                                <div className={styles.item} key={index}>
                                    <div
                                        className={`${styles.bold} ${
                                            openIndex === index ? styles.open : ""
                                        }`}
                                        onClick={() => toggleOpen(index)}>
                                        {item.title}
                                    </div>
                                    <div
                                        className={`${styles.text} ${
                                            openIndex === index ? styles.open : ""
                                        }`}
                                        dangerouslySetInnerHTML={{ __html: item.text }}></div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
}
