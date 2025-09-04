"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import Image from "next/image";
import styles from "../styles/Header.module.css";
import { usePosts } from "../lib/usePosts";

export default function Header() {
    const [menuOpen, setMenuOpen] = useState(false);
    const pathname = usePathname();
    const { data } = usePosts();

    const homePage = data?.find((page: any) => page.slug === "home");

    const socialLinks = [
        { href: homePage?.acf?.instagram, icon: "/img/menu-soc-1.svg", alt: "instagram" },
        { href: homePage?.acf?.x, icon: "/img/menu-soc-2.svg", alt: "x" },
        { href: homePage?.acf?.tiktok, icon: "/img/menu-soc-3.svg", alt: "tiktok" },
        { href: homePage?.acf?.youtube, icon: "/img/menu-soc-4.svg", alt: "youtube" },
    ];

    const menuItems = [
        { href: "/", label: "Home" },
        { href: "/video", label: "Videos" },
        { label: "Golfers", className: styles.close },
        { label: "Shop", className: styles.close },
        { href: "/#about", label: "About Us", hash: "#about" },
        { label: "Blog", className: styles.close },
        { href: "/#events", label: "Events", hash: "#events" },
        { href: "/#faq", label: "FAQs", hash: "#faq" },
    ];

    const handleClick = (e: React.MouseEvent<HTMLAnchorElement>, hash: string) => {
        if (pathname === "/") {
            e.preventDefault();
            const el = document.querySelector(hash);
            if (el) el.scrollIntoView({ behavior: "smooth" });
        }
    };

    const renderMenu = () => (
        <ul>
            {menuItems.map((item, i) => (
                <li
                    key={i}
                    className={`${item.className || ""} ${pathname === item.href ? "active" : ""}`}>
                    {item.href ? (
                        <Link
                            href={item.href}
                            onClick={item.hash ? (e) => handleClick(e, item.hash!) : undefined}>
                            {item.label}
                        </Link>
                    ) : (
                        item.label
                    )}
                </li>
            ))}
        </ul>
    );

    const renderSocials = () => (
        <div className={styles.soc}>
            {socialLinks.map(
                (soc, i) =>
                    soc.href && (
                        <a key={i} href={soc.href} target="_blank" className={styles.item}>
                            <Image src={soc.icon} alt={soc.alt} width={40} height={40} />
                        </a>
                    ),
            )}
        </div>
    );

    return (
        <>
            <div className={`${styles.menuOverlay} ${menuOpen ? styles.open : ""}`}></div>
            <div className={`${styles.menu} ${menuOpen ? styles.open : ""}`}>
                <div className={styles.box}>
                    <div className={styles.menuClose} onClick={() => setMenuOpen(!menuOpen)}></div>
                    <Link href="/" className={styles.menuLogo}>
                        <Image src="/img/logo.svg" alt="Logo" width={176} height={65} />
                    </Link>
                    <nav className={`${styles.nav} ${menuOpen ? styles.open : ""}`}>
                        {renderMenu()}
                    </nav>
                    <Link href="/sign-in" className={styles.btn}>
                        <span>Login</span>
                        <Image
                            src="/img/header-btn-arrow.svg"
                            alt="button arrow"
                            width={24}
                            height={24}
                        />
                    </Link>
                    {renderSocials()}
                </div>
            </div>

            <header className={styles.header}>
                <div className="container">
                    <div className={styles.wrapper}>
                        <Link href="/" className={styles.logo}>
                            <Image src="/img/logo.svg" alt="Logo" width={149} height={57} />
                        </Link>
                        <nav className={styles.nav}>{renderMenu()}</nav>
                        <Link href="/sign-in" className={styles.btn}>
                            <span>Login</span>
                            <Image
                                src="/img/header-btn-arrow.svg"
                                alt="button arrow"
                                width={24}
                                height={24}
                            />
                        </Link>
                        <div className={styles.burger} onClick={() => setMenuOpen(!menuOpen)}></div>
                    </div>
                </div>
            </header>
        </>
    );
}
