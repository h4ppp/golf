import "../styles/globals.css";
import ReactQueryProvider from "../lib/ReactQueryProvider";

export const metadata = {
    title: "Bikini Gold",
    description: "Golf Has Never Looked Like This",
    icons: {
        icon: "/img/favicon.svg",
        shortcut: "/img/favicon.svg",
        apple: "/img/favicon.svg",
    },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
    return (
        <html lang="en">
            <body>
                <div className="page-wrapper">
                    <ReactQueryProvider>{children}</ReactQueryProvider>
                </div>
            </body>
        </html>
    );
}
