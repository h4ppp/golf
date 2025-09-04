"use client";

import styles from "../styles/FormSection.module.css";
import Image from "next/image";
import { useState } from "react";

export default function FormSection() {
    const [formData, setFormData] = useState({
        name: "",
        email: "",
        role: "",
        location: "",
        description: "",
    });
    const [loading, setLoading] = useState(false);
    const [success, setSuccess] = useState(false);
    const [error, setError] = useState("");

    const handleChange = (
        e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>,
    ) => {
        const { name, value } = e.target;
        setFormData((prev) => ({
            ...prev,
            [name]: value,
        }));
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError("");
        setSuccess(false);

        try {
            const res = await fetch(`${process.env.NEXT_PUBLIC_SITE_URL}/api/mail.php`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(formData),
            });

            if (!res.ok) throw new Error("Ошибка при отправке формы");

            setSuccess(true);
            setFormData({
                name: "",
                email: "",
                role: "",
                location: "",
                description: "",
            });
        } catch (err: any) {
            setError(err.message || "Произошла ошибка");
        } finally {
            setLoading(false);
        }
    };

    return (
        <section className={styles.form}>
            <Image
                src="/img/form.png"
                className={styles.img}
                alt="Form"
                width={1567}
                height={1446}
            />
            <div className="container index">
                <h2 className={styles.title}>
                    Golf's Hottest <br />
                    Competition <br />
                    Starts Here!
                </h2>
                <div className={styles.subtitle}>
                    Leave your email and become part of the tournament everyone will be talking
                    about.
                </div>
                <form className={styles.formWrapper} onSubmit={handleSubmit}>
                    <div className={styles.list}>
                        <div className={styles.block}>
                            <div className="input">
                                <div className="input-title">Enter your name</div>
                                <div className="input-wrapper">
                                    <input
                                        type="text"
                                        name="name"
                                        placeholder="What should we call you?"
                                        value={formData.name}
                                        onChange={handleChange}
                                        required
                                    />
                                </div>
                            </div>
                        </div>
                        <div className={styles.block}>
                            <div className="input">
                                <div className="input-title">Enter your email</div>
                                <div className="input-wrapper">
                                    <input
                                        type="email"
                                        name="email"
                                        placeholder="Your best contact email"
                                        value={formData.email}
                                        onChange={handleChange}
                                        required
                                    />
                                </div>
                            </div>
                        </div>
                        <div className={styles.block}>
                            <div className="input">
                                <div className="input-title">Select your role (Optional)</div>
                                <div className="input-wrapper input-arrow">
                                    <select
                                        name="role"
                                        value={formData.role}
                                        onChange={handleChange}>
                                        <option value="">What's your role?</option>
                                        <option value="Player">Player</option>
                                        <option value="Organizer">Organizer</option>
                                        <option value="Sponsor">Sponsor</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        <div className={styles.block}>
                            <div className="input">
                                <div className="input-title">Select your location (Optional)</div>
                                <div className="input-wrapper input-arrow">
                                    <select
                                        name="location"
                                        value={formData.location}
                                        onChange={handleChange}>
                                        <option value="">Where are you based?</option>
                                        <option value="USA">USA</option>
                                        <option value="Europe">Europe</option>
                                        <option value="Asia">Asia</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div className="input m0">
                        <div className="input-title">Description</div>
                        <div className="input-wrapper">
                            <textarea
                                name="description"
                                placeholder="We’d love to learn more about you – feel free to share anything!"
                                value={formData.description}
                                onChange={handleChange}></textarea>
                        </div>
                    </div>
                    <button className={`btn ${styles.btn}`} type="submit" disabled={loading}>
                        {loading ? "Sending..." : "Send"}
                    </button>
                    {success && <div className="success">Message sent successfully</div>}
                    {error && <div className="error">{error}</div>}
                </form>
            </div>
        </section>
    );
}
