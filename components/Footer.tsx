"use client";

import Link from "next/link";
import styles from "../styles/Footer.module.css";
import { useState } from "react";
import { usePosts } from "../lib/usePosts";
import Image from "next/image";

export default function Footer() {
    const { data } = usePosts();

    const homePage = data?.find((page: any) => page.slug === "home");

    const socialLinks = [
        { href: homePage?.acf?.instagram, icon: "/img/soc-1.svg", alt: "instagram" },
        { href: homePage?.acf?.x, icon: "/img/soc-2.svg", alt: "x" },
        { href: homePage?.acf?.tiktok, icon: "/img/soc-3.svg", alt: "tiktok" },
        { href: homePage?.acf?.youtube, icon: "/img/soc-4.svg", alt: "youtube" },
    ];

    const menuItems = [
        { href: "/", label: "Home" },
        { href: "/video", label: "Videos" },
        { href: "/#about", label: "About Us", hash: "#about" },
        { href: "/#events", label: "Events", hash: "#events" },
        { href: "/#faq", label: "FAQs", hash: "#faq" },
    ];

    const renderMenu = () => (
        <>
            {menuItems.map((item, i) => (
                <div className={styles.item} key={i}>
                    {item.href ? (
                        <Link href={item.href} className={styles.link}>
                            {item.label}
                        </Link>
                    ) : (
                        item.label
                    )}
                    <div className={styles.line}></div>
                </div>
            ))}
        </>
    );

    const renderSocials = () => (
        <div className={styles.soc}>
            {socialLinks.map(
                (soc, i) =>
                    soc.href && (
                        <a key={i} href={soc.href} target="_blank" className={styles.socItem}>
                            <Image src={soc.icon} alt={soc.alt} width={40} height={40} />
                        </a>
                    ),
            )}
        </div>
    );

    return (
        <footer className={styles.footer}>
            <div className="container">
                <div className={styles.wrapper}>
                    <Link href="/" className={styles.logo}>
                        <Image src="/img/logo.svg" alt="Logo" width={176} height={65} />
                    </Link>

                    <div className={styles.nav}>{renderMenu()}</div>

                    <div className={styles.list}>
                        <a href={`mailto:${homePage?.acf?.email}`} className={styles.email}>
                            {homePage?.acf?.email}
                        </a>
                        {renderSocials()}
                        <a href="#" className={styles.page}>
                            Privacy Policy
                        </a>
                        <a href="#" className={styles.page}>
                            Terms of Service
                        </a>
                    </div>

                    <div className={styles.copy}>{homePage?.acf?.copy}</div>
                </div>
            </div>
        </footer>
    );
}
