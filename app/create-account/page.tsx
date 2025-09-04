"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import styles from "../../styles/Auth.module.css";
import Image from "next/image";
import Link from "next/link";

export default function CreateAccountPage() {
    const router = useRouter();
    const [form, setForm] = useState({
        email: "",
        first_name: "",
        second_name: "",
        country: "",
        password: "",
        confirmPassword: "",
    });
    const [error, setError] = useState("");
    const [showPassword, setShowPassword] = useState(false);

    const handleChange = (
        e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>,
    ) => {
        const { name, value } = e.target;
        setForm({ ...form, [name]: value });
    };

    const validate = () => {
        if (!form.email || !form.password || !form.confirmPassword)
            return "Email and password required";
        if (!form.first_name || !form.second_name || !form.country)
            return "All fields are required";
        if (!/\S+@\S+\.\S+/.test(form.email)) return "Invalid email";
        if (form.password.length < 6) return "Password must be at least 6 characters";
        if (form.password !== form.confirmPassword) return "Passwords do not match";
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

        const res = await fetch("/api/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(form),
        });

        const data = await res.json();

        if (res.ok) {
            // Успешная регистрация → перенаправляем на login
            router.push("/sign-in?registered=1");
        } else {
            setError(data.error || "Registration failed");
        }
    };

    const handleTogglePassword = () => {
        setShowPassword(!showPassword);
    };

    return (
        <section className={styles.section}>
            <div className="container">
                <div className={styles.wrapper}>
                    <Link href="/" className={styles.logo}>
                        <Image src="/img/logo.svg" alt="Logo" width={177} height={68} />{" "}
                    </Link>
                    <h1 className={styles.title}>CREATE ACCOUNT</h1>
                    <p className={styles.subtitle}>
                        Create your account by entering your details below
                    </p>

                    <form onSubmit={handleSubmit}>
                        <div className="input input-mb">
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
                        <div className="input-blocks">
                            <div className="input-block">
                                <div className="input">
                                    <div className="input-title">Enter your first name*</div>
                                    <div className="input-wrapper">
                                        <input
                                            type="text"
                                            name="first_name"
                                            placeholder="First Name*"
                                            value={form.first_name}
                                            onChange={handleChange}
                                        />
                                    </div>
                                </div>
                            </div>
                            <div className="input-block">
                                <div className="input">
                                    <div className="input-title">Enter your second name*</div>
                                    <div className="input-wrapper">
                                        <input
                                            type="text"
                                            name="second_name"
                                            placeholder="Second Name*"
                                            value={form.second_name}
                                            onChange={handleChange}
                                        />
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div className="input-blocks">
                            <div className="input-block">
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
                            </div>
                            <div className="input-block">
                                <div className="input">
                                    <div className="input-title">Confirm Password*</div>
                                    <div className="input-wrapper">
                                        <div
                                            className={`input-view ${showPassword ? "active" : ""}`}
                                            onClick={handleTogglePassword}></div>
                                        <input
                                            type={showPassword ? "text" : "password"}
                                            name="confirmPassword"
                                            placeholder="Confirm Password*"
                                            value={form.confirmPassword}
                                            onChange={handleChange}
                                        />
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div className="input mt0">
                            <div className="input-title">Select Country*</div>
                            <div className="input-wrapper input-arrow">
                                <select name="country" value={form.country} onChange={handleChange}>
                                    <option value="" disabled>
                                        Select Country*
                                    </option>
                                    <option value="us">United States</option>
                                    <option value="de">Germany</option>
                                    <option value="fr">France</option>
                                    <option value="ru">Russia</option>
                                    <option value="pl">Poland</option>
                                </select>
                            </div>
                        </div>
                        <div className={styles.btnMt}></div>
                        <button type="submit" className="btn">
                            <span>Submit</span>
                        </button>
                        {error && <div className="error">{error}</div>}
                        <div className="center">
                            <div className="form-link">
                                Already have an account?
                                <Link href="/sign-in"> Sign In</Link>
                            </div>
                        </div>
                        <div className={styles.soc}>
                            <div className={styles.socTitle}>Or sign in with</div>
                            <a href="#" className={styles.socItem}>
                                <Image src="/img/reg-1.svg" alt="facebook" width={32} height={32} />{" "}
                            </a>
                            <a href="#" className={styles.socItem}>
                                <Image src="/img/reg-2.svg" alt="google" width={32} height={32} />{" "}
                            </a>
                            <a href="#" className={styles.socItem}>
                                <Image src="/img/reg-3.svg" alt="apple" width={32} height={32} />{" "}
                            </a>
                        </div>
                    </form>
                </div>
            </div>
        </section>
    );
}
