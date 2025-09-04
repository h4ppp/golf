"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import styles from "../../styles/Auth.module.css";
import Image from "next/image";
import Link from "next/link";

export default function ForgotPasswordPage() {
    const [email, setEmail] = useState("");
    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");
    const router = useRouter();

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError("");
        setSuccess("");

        if (!email) {
            setError("Please enter your email.");
            return;
        }

        try {
            const res = await fetch(`${process.env.NEXT_PUBLIC_SITE_URL}/api/forgot-password.php`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email }),
            });

            const data = await res.json();

            if (data.success) {
                setSuccess("We sent you a password reset link to your email.");
                setEmail("");
            } else {
                setError(data.message || "Something went wrong. Try again.");
            }
        } catch (err) {
            setError("Server error. Please try later.");
        }
    };

    return (
        <section className={styles.section}>
            <div className="container">
                <div className={styles.wrapper}>
                    <Link href="/" className={styles.logo}>
                        <Image src="/img/logo.svg" alt="Logo" width={177} height={68} />
                    </Link>
                    <h1 className={styles.title}>FORGOT YOUR PASSWORD?</h1>
                    <p className={styles.subtitle}>
                        Don't worry, it happens to the best of us. <br />
                        Enter your email and we’ll send you a link to reset your password.
                    </p>

                    <form onSubmit={handleSubmit}>
                        <div className="input input-mb">
                            <div className="input-title">Enter your email*</div>
                            <div className="input-wrapper">
                                <input
                                    type="email"
                                    placeholder="Your best contact email*"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                />
                            </div>
                        </div>

                        <div className={styles.btnMt}></div>
                        <button type="submit" className="btn">
                            <span>Send Reset Link</span>
                        </button>

                        {error && <div className="error">{error}</div>}
                        {success && <div className="success">{success}</div>}

                        <div className="center">
                            <div className="form-link">
                                Remember your password? <Link href="/sign-in">Sign In</Link>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </section>
    );
}
