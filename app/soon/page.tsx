"use client";

import Link from "next/link";
import Image from "next/image";
import styles from "../../styles/Soon.module.css";
import { usePosts } from "../../lib/usePosts";

import Header from "../../components/Header";
import Footer from "../../components/Footer";

export default function SoonPage() {
    const { data } = usePosts();
    const homePage = data?.find((page: any) => page.slug === "soon");
    const acfTitle = homePage?.acf?.title;
    const acfSubtitle = homePage?.acf?.subtitle;
    const acfBtn = homePage?.acf?.btn;
    return (
        <>
            <Header />
            <section className={styles.soon}>
                <div className="container">
                    <h1 className={styles.title}>{acfTitle}</h1>
                    <p
                        className={styles.subtitle}
                        dangerouslySetInnerHTML={{ __html: acfSubtitle }}
                    />
                    <Link href="/" className={styles.btn}>
                        <Image src="/img/back.svg" alt="button arrow" width={32} height={32} />
                        <span>{acfBtn}</span>
                    </Link>
                    <Image
                        src="/img/flag.svg"
                        className={styles.img}
                        alt={styles.title}
                        width={726}
                        height={822}
                    />
                </div>
            </section>
            <Footer />
        </>
    );
}
