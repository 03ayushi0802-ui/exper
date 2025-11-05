"use client";

import React from "react";
import MyNav from "@/components/MyNav";
import Image from "next/image";
import { motion } from "framer-motion";
import Footer from "@/components/Footer";
import { MapPin, Train, Plane, Car } from "lucide-react";
import { useLanguage } from "@/contexts/LanguageContext";
import { getTranslation } from "@/lib/translations";
import LanguageSwitcher from "@/components/LanguageSwitcher";

const ReachUs = () => {
  const { language } = useLanguage();
  const t = (key) => getTranslation(language, key);

  const places = [
    {
      name: { en: "Badrinath", hi: "बद्रीनाथ" },
      time: { en: "20km", hi: "20 किमी" },
      img: "https://images.unsplash.com/photo-1601821139314-66a4d14cfc00?w=600&auto=format&fit=crop&q=60&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxjb2xsZWN0aW9uLXBhZ2V8NXwxNDk1ODQ2OXx8ZW58MHx8fHx8",
    },
    {
      name: { en: "Vasudhara Falls", hi: "वसुधारा झरना" },
      time: { en: "20km with 8 km trek", hi: "20 किमी + 8 किमी ट्रेक" },
      img: "https://imgs.search.brave.com/WTm_5h6N7HQNH5elkE0zyrQa1HLMsK0IykYTkftW3CM/rs:fit:860:0:0:0/g:ce/aHR0cHM6Ly93d3cu/dHJhd2VsbC5pbi9h/ZG1pbi9pbWFnZXMv/dXBsb2FkLzIyMjM3/NzY0N0JhZHJpbmF0/aF9WYXN1ZGhhcmFf/RmFsbHNfTWFpbi5q/cGc",
    },
    {
      name: { en: "Mana Village", hi: "माणा गांव" },
      time: { en: "22km", hi: "22 किमी" },
      img: "https://imgs.search.brave.com/ca-IJ6S0_m1UI3ArDkWHqLGmy_DtjGfk3ZGTx-Co6sI/rs:fit:860:0:0:0/g:ce/aHR0cHM6Ly9pbWdz/LnNlYXJjaC5icmF2/ZS5jb20vcVRmd2pu/aTVVaEE0X0QtT0pS/TXBxczRvVmZCcEFC/eUU3QmJJcGR0RWVV/by9yczpmaXQ6NTAw/OjA6MDowL2c6Y2Uv/YUhSMGNITTZMeTl6/TjJGdy9NUzV6WTJW/dVpUY3VZMjl0L0wy/bHpMMmx0WVdkbEwy/bHUvWTNKbFpHbGli/R1ZwYm1ScC9ZUzh4/TFcxaGJtRXRkbWxz/L2JHRm5aUzFpWVdS/eWFXNWgvZEdndGRY/UjBZWEpoYTJoaC9i/bVF0WVhSMGNpMW9a/WEp2L1AzRnNkRDA0/TWlaMGN6MHgvTnpJ/Mk5qUTJORFk0TVRJ/MQ",
    },
    {
      name: { en: "Hemkund Sahib", hi: "हेमकुंड साहिब" },
      time: { en: "5 km road with 7km trek", hi: "5 किमी + 7 किमी ट्रेक" },
      img: "https://images.unsplash.com/photo-1653545709990-a6a4c8a6c36c?w=600&auto=format&fit=crop&q=60&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxzZWFyY2h8M3x8aGVta3VuZHxlbnwwfHwwfHx8MA%3D%3D",
    },
    {
      name: { en: "Valley of Flowers", hi: "फूलों की घाटी" },
      time: { en: "20km road with 7km trek", hi: "20 किमी + 7 किमी ट्रेक" },
      img: "https://images.unsplash.com/photo-1631377649998-58947055c21d?w=600&auto=format&fit=crop&q=60&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxzZWFyY2h8Mnx8dmFsbGV5JTIwb2YlMjBmbG93ZXJzfGVufDB8fDB8fHww",
    },
  ];

  const travelModes = [
    {
      title: { en: "By Road", hi: "सड़क द्वारा" },
      desc: { 
        en: "Accessible via NH7, 22 km from Joshimath. Regular taxis and buses available from major cities.",
        hi: "NH7 से सुलभ, जोशीमठ से 22 किमी। प्रमुख शहरों से नियमित टैक्सी और बस उपलब्ध हैं।"
      },
      icon: <Car className="w-10 h-10" />,
    },
    {
      title: { en: "By Train", hi: "ट्रेन द्वारा" },
      desc: { 
        en: "Nearest railway station: Rishikesh (270 km). Taxi and bus services available to Pandukeshwar.",
        hi: "निकटतम रेलवे स्टेशन: ऋषिकेश (270 किमी)। पांडुकेश्वर के लिए टैक्सी और बस सेवाएं उपलब्ध हैं।"
      },
      icon: <Train className="w-10 h-10" />,
    },
    {
      title: { en: "By Air", hi: "हवाई मार्ग से" },
      desc: { 
        en: "Jolly Grant Airport (295 km) in Dehradun. Taxi services and buses connect to the temple.",
        hi: "देहरादून में जॉली ग्रांट हवाई अड्डा (295 किमी)। टैक्सी सेवाएं और बसें मंदिर से जुड़ी हैं।"
      },
      icon: <Plane className="w-10 h-10" />,
    },
  ];

  return (
    <div className="bg-heritage-cream min-h-screen">
      <MyNav />
      
      {/* Hero Section with Video - Heritage Design */}
      <section className="relative h-[500px] md:h-[600px] overflow-hidden">
        <video
          autoPlay
          loop
          muted
          playsInline
          className="absolute inset-0 w-full h-full object-cover"
        >
          <source src="/pandukeshwar.mp4" type="video/mp4" />
        </video>
        <div className="absolute inset-0 bg-deep-brown/50" />
        
        {/* Language Switcher */}
        <div className="absolute top-6 right-6 z-20">
          <LanguageSwitcher />
        </div>

        <div className="relative z-10 h-full flex items-center justify-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="text-center text-ivory px-4 space-y-4"
          >
            <h1 className="text-5xl md:text-6xl font-light tracking-wide" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
              {language === 'hi' ? 'पांडुकेश्वर कैसे पहुंचें' : 'How to Reach Pandukeshwar'}
            </h1>
            <p className="text-xl md:text-2xl font-light max-w-2xl mx-auto" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
              {language === 'hi' 
                ? 'हिमालय में बसे पवित्र निवास की यात्रा'
                : 'Journey to the sacred abode nestled in the Himalayas'}
            </p>
          </motion.div>
        </div>
      </section>

      {/* How to Reach Section - Heritage Design */}
      <section className="py-16 px-4 bg-ivory border-b border-sandalwood/10">
        <div className="max-w-6xl mx-auto">
          <motion.h2
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            viewport={{ once: true, amount: 0.3 }}
            className="text-4xl md:text-5xl font-light text-center text-deep-brown mb-4 tracking-wide" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}
          >
            {language === 'hi' ? 'कैसे पहुंचें' : 'How to Reach'}
          </motion.h2>
          <p className="text-center text-incense font-light mb-12 max-w-2xl mx-auto" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
            {language === 'hi' 
              ? 'कुबेरजी के दिव्य मंदिर की आपकी यात्रा'
              : 'Your journey to the divine temple of KuberJi'}
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {travelModes.map((mode, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: index * 0.05 }}
                viewport={{ once: true, amount: 0.2 }}
                className="bg-heritage-cream border border-sandalwood/15 rounded-sm p-8 shadow-sm hover:shadow-md transition-all duration-300"
              >
                <div className="text-sandalwood mb-4 flex justify-center">
                  {mode.icon}
                </div>
                <h3 className="text-2xl font-light text-center mb-4 text-deep-brown" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
                  {mode.title[language]}
                </h3>
                <p className="text-center text-incense font-light leading-relaxed" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                  {mode.desc[language]}
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Nearby Attractions - Heritage Design */}
      <section className="py-16 px-4">
        <div className="max-w-6xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            viewport={{ once: true }}
            className="text-center mb-12 space-y-4"
          >
            <h2 className="text-4xl md:text-5xl font-light text-deep-brown tracking-wide" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
              {language === 'hi' ? 'आस-पास के आकर्षण' : 'Nearby Attractions'}
            </h2>
            <p className="text-incense font-light text-lg" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
              {language === 'hi'
                ? 'पांडुकेश्वर के आसपास पवित्र और प्राकृतिक स्थानों का अन्वेषण करें'
                : 'Explore sacred and scenic places around Pandukeshwar'}
            </p>
          </motion.div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-8">
            {places.map((place, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 50 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.8, ease: "easeInOut", delay: index * 0.1 }}
                viewport={{ once: true }}
                className="bg-ivory border border-sandalwood/15 rounded-sm overflow-hidden shadow-sm hover:shadow-md transition-all duration-300 group"
              >
                <div className="relative h-48 overflow-hidden">
                  <Image
                    height={200}
                    width={400}
                    src={place.img}
                    alt={place.name[language]}
                    className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
                    loading="lazy"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-deep-brown/50 to-transparent" />
                </div>
                <div className="p-6 space-y-2">
                  <h3 className="text-xl font-light text-deep-brown" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
                    {place.name[language]}
                  </h3>
                  <div className="flex items-center text-incense font-light">
                    <MapPin className="w-4 h-4 mr-2 text-sandalwood" />
                    <p className="text-sm" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                      {place.time[language]}
                    </p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>
      
      <Footer />
    </div>
  );
};

export default ReachUs;
