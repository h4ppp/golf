import Header from "../../components/Header";
import FavoriteVideos from "../../components/FavoriteVideos";
import RecommendedVideos from "../../components/RecommendedVideos";
import Footer from "../../components/Footer";
import styles from "../../styles/Video.module.css";

export default function VideoPage() {
    return (
        <>
            <Header />
            <section className={styles.video}>
                <div className="container">
                    <div className={styles.wrapper}>
                        <h1 className={styles.title}>
                            Golf Has Never <span>Looked Like This</span>
                        </h1>
                        <div className={styles.subtitle}>
                            In our footage, golf transforms into the aesthetics of an easy, carefree
                            life in the tropics.
                        </div>
                    </div>
                </div>
            </section>
            <section className="section"></section>
            <FavoriteVideos />
            <RecommendedVideos favoriteMode={false} sectionTitle="Recommended Video " />
            <Footer />
        </>
    );
}
