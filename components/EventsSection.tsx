"use client";

import { useState, useRef } from "react";
import Image from "next/image";
import { useEvents } from "../lib/useEvents";

import { Swiper, SwiperSlide } from "swiper/react";
import SwiperCore from "swiper";

import "swiper/css";
//import "swiper/css/navigation";
//import "swiper/css/thumbs";
import "swiper/css/pagination";

import styles from "../styles/EventsSection.module.css";

SwiperCore.use([]);

export default function EventsSection() {
    const [mainSwiper, setMainSwiper] = useState<SwiperCore | null>(null);
    const { data: events = [] } = useEvents();

    const handlePrev = () => {
        mainSwiper?.slidePrev();
    };

    const handleNext = () => {
        mainSwiper?.slideNext();
    };

    return (
        <section className={`${styles.events} events`} id="events">
            <div className="container">
                <div className={styles.top}>
                    <h2 className={styles.title}>EVENTS</h2>
                    <div className={styles.arrows}>
                        <div className={`${styles.arrow} ${styles.prev} btn`} onClick={handlePrev}>
                            <span>Previos</span>
                            <Image src="/img/next.svg" alt="arrow" width={46} height={43} />
                        </div>
                        <div className={`${styles.arrow} ${styles.next} btn`} onClick={handleNext}>
                            <span>NEXT</span>
                            <Image src="/img/next.svg" alt="arrow" width={46} height={43} />
                        </div>
                    </div>
                </div>
                <Swiper
                    onSwiper={setMainSwiper}
                    spaceBetween={20}
                    loop={true}
                    slidesPerView={3}
                    pagination={{ clickable: true }}
                    className={styles.recSlider}
                    breakpoints={{
                        0: {
                            slidesPerView: 1,
                        },
                        768: {
                            slidesPerView: 2,
                        },
                        1251: {
                            slidesPerView: 3,
                        },
                    }}>
                    {events.map((event) => (
                        <SwiperSlide key={event.id} className={styles.eventSlider}>
                            <div className={styles.eventItem}>
                                <div className={styles.eventAfter}>
                                    <img src="/img/arrow.svg" alt="arrow" width={93} height={93} />
                                </div>
                                {(event as any)?.img && (
                                    <img
                                        src={(event as any).img}
                                        className={styles.eventImg}
                                        alt={event.title.rendered}
                                        width={559}
                                        height={442}
                                    />
                                )}
                                <div className={styles.date}>
                                    <span>{(event as any)?.date}</span>
                                </div>
                                <div className={styles.eventWrapper}>
                                    <div className={styles.eventBold}>{event?.title.rendered}</div>
                                    {(event as any)?.text && (
                                        <p
                                            className={styles.eventText}
                                            dangerouslySetInnerHTML={{
                                                __html: (event as any)?.text,
                                            }}
                                        />
                                    )}
                                </div>
                            </div>
                        </SwiperSlide>
                    ))}
                </Swiper>
            </div>
        </section>
    );
}
