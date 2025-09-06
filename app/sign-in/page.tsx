"use client";

import styles from "../../styles/Auth.module.css";
import Image from "next/image";
import Link from "next/link";
import { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { type Dispatch, type SetStateAction } from "react";

interface SearchParamsHandlerProps {
    setSuccess: Dispatch<SetStateAction<string>>;
}

function SearchParamsHandler({ setSuccess }: SearchParamsHandlerProps) {
    const searchParams = useSearchParams();

    useEffect(() => {
        if (searchParams.get("registered") === "1") {
            setSuccess("Registration successful! Please login.");
        }
    }, [searchParams, setSuccess]);

    return null;
}

export default function SignInPage() {
    const router = useRouter();
    const [form, setForm] = useState({ email: "", password: "" });
    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");
    const [showPassword, setShowPassword] = useState(false);

    const handleChange = (
        e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>,
    ) => {
        const { name, value } = e.target;
        setForm({ ...form, [name]: value });
    };

    const validate = () => {
        if (!form.email || !form.password) return "Email and password required";
        if (!/\S+@\S+\.\S+/.test(form.email)) return "Invalid email";
        if (form.password.length < 6) return "Password must be at least 6 characters";
        return "";
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        const validationError = validate();
        if (validationError) {
            setError(validationError);
            return;
        }
        setError("");

        try {
            const res = await fetch("/api/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(form),
            });

            const data = await res.json();
            console.log("LOGIN RESPONSE:", data);

            if (res.ok) {
                router.push("/account");
            } else {
                setError(data.error || "Login failed");
            }
        } catch (err) {
            console.error("LOGIN REQUEST ERROR:", err);
            setError("Something went wrong");
        }
    };

    const handleTogglePassword = () => {
        setShowPassword(!showPassword);
    };

    return (
        <section className={styles.section}>
            <Suspense fallback={null}>
                <SearchParamsHandler setSuccess={setSuccess} />
            </Suspense>

            <div className="container">
                <div className={styles.wrapper}>
                    <Link href="/" className={styles.logo}>
                        <Image src="/img/logo.svg" alt="Logo" width={177} height={68} />
                    </Link>
                    <h1 className={styles.title}>Sign In</h1>
                    <p className={styles.subtitle}>
                        Welcome back! Log in to your account to get back to the game.
                    </p>
                    <form onSubmit={handleSubmit}>
                        <div className="input">
                            <div className="input-title">Enter your email*</div>
                            <div className="input-wrapper">
                                <input
                                    name="email"
                                    placeholder="Your best contact email*"
                                    value={form.email}
                                    onChange={handleChange}
                                />
                            </div>
                        </div>
                        <div className="input">
                            <div className="input-title">Password*</div>
                            <div className="input-wrapper">
                                <div
                                    className={`input-view ${showPassword ? "active" : ""}`}
                                    onClick={handleTogglePassword}></div>
                                <input
                                    type={showPassword ? "text" : "password"}
                                    name="password"
                                    placeholder="Password*"
                                    value={form.password}
                                    onChange={handleChange}
                                />
                            </div>
                        </div>
                        <div className={styles.btnMt}></div>
                        <button type="submit" className="btn">
                            <span>SIGN IN</span>
                        </button>
                        {success && <div className="success">{success}</div>}
                        {error && <div className="error">{error}</div>}
                        <div className="center">
                            <div className="form-link">
                                <Link href="/">Forgot your password?</Link>
                            </div>
                        </div>
                        <div className={styles.soc}>
                            <div className={styles.socTitle}>Or sign in with</div>
                            <a href="#" className={styles.socItem}>
                                <Image src="/img/reg-1.svg" alt="facebook" width={32} height={32} />
                            </a>
                            <a href="#" className={styles.socItem}>
                                <Image src="/img/reg-2.svg" alt="google" width={32} height={32} />
                            </a>
                            <a href="#" className={styles.socItem}>
                                <Image src="/img/reg-3.svg" alt="apple" width={32} height={32} />
                            </a>
                        </div>
                    </form>
                </div>
            </div>
        </section>
    );
}
