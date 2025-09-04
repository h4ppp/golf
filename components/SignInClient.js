"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";

export default function SignInClient({ setSuccess }) {
    const searchParams = useSearchParams();
    const [isClient, setIsClient] = useState(false);

    useEffect(() => {
        setIsClient(true);
    }, []);

    useEffect(() => {
        if (isClient && searchParams.get("registered") === "1") {
            setSuccess("Registration successful! Please login.");
        }
    }, [searchParams, isClient, setSuccess]);

    return null;
}
