"use client";

import styles from "../../styles/Auth.module.css";
import Image from "next/image";
import Link from "next/link";
import { useEffect, useState, useMemo } from "react";
import { useRouter } from "next/navigation";

import Header from "../../components/Header";
import Footer from "../../components/Footer";
import RecommendedVideos from "@/components/RecommendedVideos";

interface Video {
    url: string;
}
interface ProfileData {
    email: string;
    first_name: string;
    second_name: string;
    favorite_videos: string | null; // может быть JSON-строкой
}

export default function AccountPage() {
    const router = useRouter();
    const [data, setData] = useState<ProfileData | null>(null);
    const [showEditName, setShowEditName] = useState(false);
    const [showChangePassword, setShowChangePassword] = useState(false);
    const [message, setMessage] = useState("");
    const [nameForm, setNameForm] = useState({ first_name: "", second_name: "" });
    const [passwordForm, setPasswordForm] = useState({
        currentPassword: "",
        newPassword: "",
        confirmPassword: "",
    });
    const [showPassword, setShowPassword] = useState(false);

    useEffect(() => {
        fetch("/api/profile")
            .then((res) => {
                if (res.status === 401) router.push("/sign-in");
                return res.json();
            })
            .then((d) => {
                if (d) {
                    setData(d);
                    setNameForm({
                        first_name: d.first_name,
                        second_name: d.second_name,
                    });
                }
            })
            .catch(() => {});
    }, [router]);

    const handleLogout = async () => {
        await fetch("/api/logout", { method: "POST" });
        router.push("/sign-in");
    };

    const handleTogglePassword = () => {
        setShowPassword(!showPassword);
    };

    // Изменение имени
    const handleNameSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        const res = await fetch("/api/profile/edit-name", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(nameForm),
        });
        const result = await res.json();
        if (res.ok) {
            setData((prev) => (prev ? { ...prev, ...nameForm } : prev));
            setMessage("Name updated successfully!");
            setShowEditName(false);
        } else {
            setMessage(result.error || "Failed to update name");
        }
    };

    // Изменение пароля
    const handlePasswordSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (passwordForm.newPassword !== passwordForm.confirmPassword) {
            setMessage("New passwords do not match");
            return;
        }

        const res = await fetch("/api/profile/change-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(passwordForm),
        });
        const result = await res.json();
        if (res.ok) {
            setMessage("Password changed successfully!");
            setShowChangePassword(false);
            setPasswordForm({ currentPassword: "", newPassword: "", confirmPassword: "" });
        } else {
            setMessage(result.error || "Failed to change password");
        }
    };

    // безопасно парсим favorite_videos в массив чисел
    const favoriteVideoIds = useMemo(() => {
        if (!data?.favorite_videos) return [];

        try {
            const parsed = JSON.parse(data.favorite_videos);

            if (Array.isArray(parsed)) return parsed.map((id) => Number(id));

            if (!isNaN(Number(parsed))) return [Number(parsed)];

            return [];
        } catch {
            return data.favorite_videos
                .split(",")
                .map((id) => Number(id.trim()))
                .filter(Boolean);
        }
    }, [data?.favorite_videos]);

    let name = "";
    data ? (name = data.first_name) : "";

    return (
        <>
            <Header />
            <section className={styles.account}>
                <div className={styles.accountTop}>
                    <div className="container">
                        <h1 className={styles.accountTitle}>Welcome back, {name}!</h1>
                    </div>
                </div>
                <div className="container">
                    <div className={styles.accountBold}>Account Details</div>
                    <div className={styles.accountList}>
                        {data ? (
                            <>
                                <div className={styles.accountBlock}>
                                    <div className={styles.accountItemTitle}>Email:</div>
                                    <div className={styles.accountText}>{data.email}</div>
                                </div>
                                <div className={styles.accountBlock}>
                                    <div className={styles.accountItemTitle}>Name:</div>
                                    <div className={styles.accountText}>{data.first_name}</div>
                                    <button
                                        className={styles.btnPopup}
                                        onClick={() => setShowEditName(true)}>
                                        Edit
                                    </button>
                                </div>
                                <div className={styles.accountBlock}>
                                    <div className={styles.accountItemTitle}>Password:</div>
                                    <div className={styles.accountText}>{data.second_name}</div>
                                    <button
                                        className={styles.btnPopup}
                                        onClick={() => setShowChangePassword(true)}>
                                        Change Password
                                    </button>
                                </div>

                                <button className="btn logout" onClick={handleLogout}>
                                    <span>Logout</span>
                                    <Image
                                        src="/img/header-btn-arrow.svg"
                                        alt="button arrow"
                                        width={24}
                                        height={24}
                                    />
                                </button>
                            </>
                        ) : (
                            <></>
                        )}
                    </div>
                </div>

                {/* Попап Edit Name */}
                {showEditName && (
                    <>
                        <div className="modal">
                            <div
                                className="modal-overlay"
                                onClick={() => setShowEditName(false)}></div>
                            <div className="modal-list">
                                <div className="modal-container">
                                    <div
                                        className="modal-close"
                                        onClick={() => setShowEditName(false)}></div>
                                    <h3 className="modal-title">Edit Name</h3>
                                    <form onSubmit={handleNameSubmit}>
                                        <div className="input input-mb">
                                            <div className="input-title">Edit your first name</div>
                                            <div className="input-wrapper">
                                                <input
                                                    name="first_name"
                                                    placeholder="First Name"
                                                    value={nameForm.first_name}
                                                    onChange={(e) =>
                                                        setNameForm({
                                                            ...nameForm,
                                                            first_name: e.target.value,
                                                        })
                                                    }
                                                />
                                            </div>
                                        </div>
                                        <div className="input">
                                            <div className="input-title">Edit your second name</div>
                                            <div className="input-wrapper">
                                                <input
                                                    name="second_name"
                                                    placeholder="Second Name"
                                                    value={nameForm.second_name}
                                                    onChange={(e) =>
                                                        setNameForm({
                                                            ...nameForm,
                                                            second_name: e.target.value,
                                                        })
                                                    }
                                                />
                                            </div>
                                        </div>
                                        <button type="submit" className="btn btn-modal">
                                            Update name
                                        </button>
                                        <div
                                            className="btn btn-red"
                                            onClick={() => setShowEditName(false)}>
                                            Cancel
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </>
                )}

                {/* Попап Change Password */}
                {showChangePassword && (
                    <>
                        <div className="modal">
                            <div
                                className="modal-overlay"
                                onClick={() => setShowChangePassword(false)}></div>
                            <div className="modal-list">
                                <div className="modal-container">
                                    <div
                                        className="modal-close"
                                        onClick={() => setShowChangePassword(false)}></div>
                                    <h3 className="modal-title">Change Password</h3>
                                    <form onSubmit={handlePasswordSubmit}>
                                        <div className="input-mb">
                                            <div className="input modal-input">
                                                <div className="input-title">New Password*</div>
                                                <div className="input-wrapper">
                                                    <div
                                                        className={`input-view ${
                                                            showPassword ? "active" : ""
                                                        }`}
                                                        onClick={handleTogglePassword}></div>
                                                    <input
                                                        type={showPassword ? "text" : "password"}
                                                        name="password"
                                                        placeholder="Create new password"
                                                        value={passwordForm.newPassword}
                                                        onChange={(e) =>
                                                            setPasswordForm({
                                                                ...passwordForm,
                                                                newPassword: e.target.value,
                                                            })
                                                        }
                                                    />
                                                </div>
                                            </div>
                                        </div>

                                        <div className="input modal-input">
                                            <div className="input-title">Confirm Password* </div>
                                            <div className="input-wrapper">
                                                <div
                                                    className={`input-view ${
                                                        showPassword ? "active" : ""
                                                    }`}
                                                    onClick={handleTogglePassword}></div>
                                                <input
                                                    type={showPassword ? "text" : "password"}
                                                    name="confirmPassword"
                                                    placeholder="Re-enter your new password"
                                                    value={passwordForm.confirmPassword}
                                                    onChange={(e) =>
                                                        setPasswordForm({
                                                            ...passwordForm,
                                                            confirmPassword: e.target.value,
                                                        })
                                                    }
                                                />
                                            </div>
                                        </div>

                                        <button type="submit" className="btn btn-modal">
                                            Update name
                                        </button>
                                        <button
                                            className="btn btn-red"
                                            onClick={() => setShowChangePassword(false)}>
                                            RESET PASSWORD
                                        </button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </>
                )}
                <div className="container">
                    {message && <div className="success">{message}</div>}
                </div>
            </section>
            {data && (
                <RecommendedVideos
                    favoriteMode={true}
                    sectionTitle="Favorite Videos"
                    favoriteVideos={favoriteVideoIds}
                />
            )}

            <Footer />
        </>
    );
}
