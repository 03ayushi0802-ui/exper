"use client";
import { useState } from "react";
import MyNav from "@/components/MyNav";
import Footer from "@/components/Footer";
import Image from "next/image";
import { motion, AnimatePresence } from "framer-motion";
import { X } from "lucide-react";
import { useLanguage } from "@/contexts/LanguageContext";
import { getTranslation } from "@/lib/translations";
import LanguageSwitcher from "@/components/LanguageSwitcher";

export default function MediaPage() {
  const { language } = useLanguage();
  const t = (key) => getTranslation(language, key);
  const [selectedImage, setSelectedImage] = useState(null);
  const [selectedCategory, setSelectedCategory] = useState("all");

  const galleryImages = [
    {
      src: "/images/temple/temple-top-2.jpeg",
      titleKey: "media.templeExterior",
      category: "temple",
    },
    {
      src: "/images/kuberji/kuberji1.jpeg",
      titleKey: "media.mainSanctum",
      category: "temple",
    },
    {
      src: "/images/kuberji/kuber-chowk-3.jpeg",
      titleKey: "media.templeCourtyard",
      category: "temple",
    },
    {
      src: "/images/milkbath2.jpeg",
      titleKey: "media.abhishekamCeremony",
      category: "rituals",
    },
    {
      src: "/images/carryin2.jpeg",
      titleKey: "media.devoteesGathering",
      category: "rituals",
    },
    {
      src: "/images/kalas-high.jpg",
      titleKey: "media.sacredKalash",
      category: "rituals",
    },
    {
      src: "/images/sitting.jpeg",
      titleKey: "media.templePriests",
      category: "people",
    },
    {
      src: "/images/carrying.jpeg",
      titleKey: "media.templeProcession",
      category: "rituals",
    },
    {
      src: "/images/riverfront.jpg",
      titleKey: "media.alaknandaRiver",
      category: "nature",
    },
    {
      src: "/images/village.jpg",
      titleKey: "media.pandukeshwarVillage",
      category: "nature",
    },
    {
      src: "/images/pandukeshwar-snow.jpeg",
      titleKey: "media.winterSeason",
      category: "nature",
    },
    {
      src: "/images/firewalk.jpeg",
      titleKey: "media.fireCeremony",
      category: "rituals",
    },
  ];

  const categories = [
    { id: "all", labelKey: "media.all" },
    { id: "temple", labelKey: "media.temple" },
    { id: "rituals", labelKey: "media.rituals" },
    { id: "people", labelKey: "media.people" },
    { id: "nature", labelKey: "media.nature" },
  ];

  const filteredImages =
    selectedCategory === "all"
      ? galleryImages
      : galleryImages.filter((img) => img.category === selectedCategory);

  return (
    <div className="bg-heritage-cream min-h-screen">
      <MyNav />

      {/* Hero Banner - Heritage Design */}
      <section className="relative py-20 px-4 bg-ivory border-b border-sandalwood/10">
        {/* Subtle Pattern */}
        <div className="absolute inset-0 opacity-[0.015]">
          <div className="w-full h-full" style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Ctext x='30' y='35' text-anchor='middle' font-size='24' fill='%238B4513'%3Eॐ%3C/text%3E%3C/svg%3E")`,
            backgroundSize: '60px 60px'
          }}></div>
        </div>

        {/* Language Switcher */}
        <div className="absolute top-6 right-6 z-20">
          <LanguageSwitcher />
        </div>

        <div className="relative max-w-4xl mx-auto text-center space-y-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            viewport={{ once: true }}
          >
            <h1 className="text-5xl md:text-6xl font-light text-deep-brown tracking-wide" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
              {t('media.title')}
            </h1>
            <p className="text-lg text-incense font-light max-w-2xl mx-auto" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
              {t('media.subtitle')}
            </p>
          </motion.div>
        </div>
      </section>

      {/* Category Filter */}
      <div className="sticky top-20 z-40 bg-ivory shadow-sm py-6 border-b border-sandalwood/10">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex flex-wrap gap-3 justify-center">
            {categories.map((cat) => (
              <motion.button
                key={cat.id}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                transition={{ duration: 0.2 }}
                onClick={() => setSelectedCategory(cat.id)}
                className={`px-6 py-2 rounded-sm font-light transition-all duration-300 ${
                  selectedCategory === cat.id
                    ? "bg-sandalwood text-ivory shadow-sm"
                    : "bg-heritage-cream text-deep-brown hover:bg-sandalwood/10 border border-sandalwood/20"
                }`}
                style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}
              >
                {t(cat.labelKey)}
              </motion.button>
            ))}
          </div>
        </div>
      </div>

      {/* Gallery Grid */}
      <section className="py-16 px-4 max-w-7xl mx-auto">
        <motion.div
          layout
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6"
        >
          <AnimatePresence mode="wait">
            {filteredImages.map((image, idx) => (
              <motion.div
                key={image.src}
                layout
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                transition={{ duration: 0.3 }}
                className="relative h-80 rounded-sm overflow-hidden group cursor-pointer shadow-sm hover:shadow-md transition-shadow border border-sandalwood/10"
                onClick={() => setSelectedImage(image)}
              >
                <Image
                  src={image.src}
                  alt={t(image.titleKey)}
                  fill
                  className="object-cover group-hover:scale-105 transition-transform duration-500"
                  loading="lazy"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/70 via-black/0 to-black/0 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                  <div className="absolute bottom-0 left-0 right-0 p-4">
                    <h3 className="text-white font-light text-lg" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                      {t(image.titleKey)}
                    </h3>
                  </div>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </motion.div>
      </section>

      {/* Lightbox */}
      <AnimatePresence>
        {selectedImage && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 bg-black/95 z-50 flex items-center justify-center p-4"
            onClick={() => setSelectedImage(null)}
          >
            <button
              onClick={() => setSelectedImage(null)}
              className="absolute top-4 right-4 w-12 h-12 rounded-full bg-white/10 backdrop-blur flex items-center justify-center hover:bg-white/20 transition-colors"
              aria-label="Close"
            >
              <X className="w-6 h-6 text-white" />
            </button>

            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="relative max-w-6xl w-full h-[80vh]"
              onClick={(e) => e.stopPropagation()}
            >
              <Image
                src={selectedImage.src}
                alt={t(selectedImage.titleKey)}
                fill
                className="object-contain"
              />
              <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/80 to-transparent p-6">
                <h2 className="text-white text-2xl font-light" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
                  {t(selectedImage.titleKey)}
                </h2>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <Footer />
    </div>
  );
}
