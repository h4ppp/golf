"use client";

import { useState, Suspense, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import styles from "../../styles/Auth.module.css";
import Image from "next/image";
import Link from "next/link";
import { type Dispatch, type SetStateAction } from "react";

interface SearchParamsHandlerProps {
    setToken: Dispatch<SetStateAction<string | null>>;
}

function SearchParamsHandler({ setToken }: SearchParamsHandlerProps) {
    const searchParams = useSearchParams();

    useEffect(() => {
        setToken(searchParams.get("token"));
    }, [searchParams, setToken]);

    return null;
}

export default function ResetPasswordPage() {
    const [password, setPassword] = useState("");
    const [confirm, setConfirm] = useState("");
    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");
    const [token, setToken] = useState<string | null>(null);
    const router = useRouter();
    const [showPassword, setShowPassword] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError("");
        setSuccess("");

        if (!password || !confirm) {
            setError("All fields are required.");
            return;
        }
        if (password !== confirm) {
            setError("Passwords do not match.");
            return;
        }
        if (!token) {
            setError("Missing reset token.");
            return;
        }

        try {
            const res = await fetch(`${process.env.NEXT_PUBLIC_SITE_URL}/api/reset-password.php`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ token, password }),
            });

            const data = await res.json();

            if (data.success) {
                setSuccess("Password successfully updated.");
                setTimeout(() => {
                    router.push("/account");
                }, 2000);
            } else {
                setError(data.message || "Something went wrong. Try again.");
            }
        } catch (err) {
            setError("Server error. Please try later.");
        }
    };

    const handleTogglePassword = () => {
        setShowPassword(!showPassword);
    };

    return (
        <section className={styles.section}>
            <Suspense fallback={null}>
                <SearchParamsHandler setToken={setToken} />
            </Suspense>

            <div className="container">
                <div className={styles.wrapper}>
                    <Link href="/" className={styles.logo}>
                        <Image src="/img/logo.svg" alt="Logo" width={177} height={68} />
                    </Link>

                    <h1 className={styles.title}>RESET PASSWORD</h1>
                    <p className={styles.subtitle}>
                        Create a new password for your account. <br />
                        Make sure it’s something strong and easy to remember.
                    </p>

                    <form onSubmit={handleSubmit}>
                        <div className="input-mb">
                            <div className="input">
                                <div className="input-title">New Password*</div>
                                <div className="input-wrapper">
                                    <div
                                        className={`input-view ${showPassword ? "active" : ""}`}
                                        onClick={handleTogglePassword}></div>
                                    <input
                                        type={showPassword ? "text" : "password"}
                                        name="password"
                                        placeholder="Create new password"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                    />
                                </div>
                            </div>
                        </div>

                        <div className="input">
                            <div className="input-title">Confirm Password* </div>
                            <div className="input-wrapper">
                                <div
                                    className={`input-view ${showPassword ? "active" : ""}`}
                                    onClick={handleTogglePassword}></div>
                                <input
                                    type={showPassword ? "text" : "password"}
                                    name="confirmPassword"
                                    placeholder="Re-enter your new password"
                                    value={confirm}
                                    onChange={(e) => setConfirm(e.target.value)}
                                />
                            </div>
                        </div>

                        <div className={styles.btnMt}></div>
                        <button type="submit" className="btn">
                            <span>RESET PASSWORD</span>
                        </button>

                        {error && <div className="error">{error}</div>}
                        {success && <div className="success">{success}</div>}

                        <div className="center">
                            <div className="form-link">
                                Remembered it last minute? <Link href="/sign-in">Sign In</Link>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </section>
    );
}
