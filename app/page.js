"use client";
import MyNav from "@/components/MyNav";
import Footer from "@/components/Footer";
import Image from "next/image";
import Link from "next/link";
import { motion } from "framer-motion";
import { useLanguage } from "@/contexts/LanguageContext";
import { getTranslation } from "@/lib/translations";
import LanguageSwitcher from "@/components/LanguageSwitcher";

export default function Home() {
  const { language } = useLanguage();
  const t = (key) => getTranslation(language, key);

  const services = [
    {
      title: t("serviceCards.dailyRituals.title"),
      desc: t("serviceCards.dailyRituals.desc"),
      img: "/images/sitting.jpeg",
    },
    {
      title: t("serviceCards.abhishekam.title"),
      desc: t("serviceCards.abhishekam.desc"),
      img: "/images/milkbath2.jpeg",
    },
    {
      title: t("serviceCards.prasadSeva.title"),
      desc: t("serviceCards.prasadSeva.desc"),
      img: "/images/carryin2.jpeg",
    },
  ];

  return (
    <div className="bg-heritage-cream">
      <MyNav />
      
      {/* Hero Section - Heritage Design */}
      <section className="relative min-h-[600px] md:min-h-[700px] overflow-hidden bg-ivory">
        {/* Subtle Heritage Pattern */}
        <div className="absolute inset-0 opacity-[0.015]">
          <div className="w-full h-full" style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg width='80' height='80' viewBox='0 0 80 80' xmlns='http://www.w3.org/2000/svg'%3E%3Ctext x='40' y='45' text-anchor='middle' font-size='28' fill='%238B4513'%3Eॐ%3C/text%3E%3C/svg%3E")`,
            backgroundSize: '80px 80px'
          }}></div>
        </div>

        {/* Language Switcher - Fixed Position */}
        <div className="absolute top-6 right-6 z-20">
          <LanguageSwitcher />
        </div>
        

        <div className="relative grid md:grid-cols-2 min-h-[600px] md:min-h-[700px]">
          {/* Left: Content */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6, ease: "easeOut" }}
            className="flex flex-col justify-center px-6 md:px-12 lg:px-20 py-20 bg-heritage-cream/90"
          >
            <div className="max-w-xl space-y-6">
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.2, duration: 0.5 }}
                className="text-sandalwood text-xs font-light tracking-[0.3em] uppercase block"
                style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}
              >
                {t('home.subtitle')}
              </motion.span>
              
              <h1 className="text-5xl md:text-7xl font-light text-deep-brown leading-tight tracking-wide" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
                {t('home.title')}
              </h1>
              
              <p className="text-incense text-base md:text-lg leading-relaxed font-light">
                {t('home.description')}
              </p>
              
              <div className="flex flex-col sm:flex-row gap-3 pt-4">
                <Link href="/aarti-pooja">
                  <button className="bg-sandalwood text-ivory px-8 py-3 rounded-sm font-light transition-all duration-300 hover:bg-deep-brown border border-sandalwood shadow-sm" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
                    {t('home.bookAarti')}
                  </button>
                </Link>
                <Link href="/howtoreachus">
                  <button className="border border-sandalwood/30 text-deep-brown hover:bg-sandalwood/5 px-8 py-3 rounded-sm font-light transition-all duration-300" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                    {t('home.planVisit')}
                  </button>
                </Link>
                <Link href="/about">
                  <button className="border border-sandalwood/30 text-deep-brown hover:bg-sandalwood/5 px-8 py-3 rounded-sm font-light transition-all duration-300" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                    {t('home.learnMore')}
                  </button>
                </Link>
              </div>
            </div>
          </motion.div>

          {/* Right: Image */}
          <motion.div
            initial={{ opacity: 0, scale: 1.02 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.6, ease: "easeOut" }}
            className="relative min-h-[400px] md:min-h-full"
          >
            <Image
              src="/images/kuberji/kuberji1.jpeg"
              alt="KuberJi Mandir"
              fill
              className="object-cover"
              priority
            />
            <div className="absolute inset-0 bg-gradient-to-l from-transparent via-transparent to-heritage-cream/10" />
          </motion.div>
        </div>
      </section>

      {/* Stats Section - Heritage Minimal */}
      <section className="py-20 bg-sandalwood/5 border-y border-sandalwood/10">
        <div className="max-w-6xl mx-auto px-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
            {[
              { number: "1000+", label: language === 'hi' ? "वर्षों की विरासत" : "Years of Heritage" },
              { number: "365", label: language === 'hi' ? "दिनों की प्रार्थना" : "Days of Prayer" },
              { number: "50+", label: language === 'hi' ? "वार्षिक कार्यक्रम" : "Annual Events" },
              { number: "ॐ", label: language === 'hi' ? "आशीर्वाद" : "Blessings" },
            ].map((stat, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, y: 15 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: idx * 0.05 }}
                viewport={{ once: true, amount: 0.3 }}
                className="space-y-2"
              >
                <div className="text-4xl md:text-5xl font-light text-sandalwood" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
                  {stat.number}
                </div>
                <div className="text-sm md:text-base text-incense font-light" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                  {stat.label}
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* About Section - Minimal */}
      <section className="py-20 px-4 max-w-6xl mx-auto bg-white">
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          viewport={{ once: true, amount: 0.2 }}
          className="grid md:grid-cols-2 gap-12 items-center"
        >
          <div className="relative h-[400px] md:h-[500px] rounded overflow-hidden shadow-xl order-2 md:order-1">
            <Image
              src="/images/milkbath2.jpeg"
              alt="Temple Ceremony"
              fill
              className="object-cover hover:scale-105 transition-transform duration-500"
              loading="lazy"
            />
          </div>
          <div className="order-1 md:order-2">
           <span className="text-[#C97A3C] text-sm font-semibold tracking-wider uppercase mb-3 block">
        {t("heritageSection.tagline")}
      </span>
      <h2 className="text-4xl font-bold text-[#5A3825] mb-6 leading-tight">
        {t("heritageSection.title")}
      </h2>
      <p className="text-lg text-gray-700 leading-relaxed mb-4">
        {t("heritageSection.paragraph1")}
      </p>
      <p className="text-lg text-gray-700 leading-relaxed mb-6">
        {t("heritageSection.paragraph2")}
      </p>
      <Link href="/about">
        <button className="bg-[#C97A3C] hover:bg-[#B5682B] text-white px-6 py-3 rounded font-semibold transition-all duration-300">
          {t("heritageSection.button")}
        </button>
      </Link>
          </div>
        </motion.div>
      </section>

      {/* Gallery Preview */}
      <section className="py-20 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4">
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            viewport={{ once: true, amount: 0.3 }}
            className="text-center mb-12"
          >
            <h2 className="text-4xl font-bold text-spiritual-green mb-4 font-quicksand">
        {t("gallerySection.title")}
      </h2>
      <p className="text-gray-600 text-lg">
        {t("gallerySection.description")}
      </p>
          </motion.div>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            {[
              "/images/temple/temple-top-2.jpeg",
              "/images/kuberji/kuber-chowk-3.jpeg",
              "/images/milkbath2.jpeg",
              "/images/carryin2.jpeg",
            ].map((img, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, scale: 0.95 }}
                whileInView={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.4, delay: idx * 0.05 }}
                viewport={{ once: true, amount: 0.2 }}
                className="relative h-64 rounded-lg overflow-hidden group cursor-pointer"
              >
                <Image
                  src={img}
                  alt={`Gallery ${idx + 1}`}
                  fill
                  className="object-cover group-hover:scale-110 transition-transform duration-500"
                  loading="lazy"
                />
              </motion.div>
            ))}
          </div>
          
          <div className="text-center">
            <Link href="/media">
              <button className="border-2 border-spiritual-gold text-spiritual-gold hover:bg-spiritual-gold hover:text-white px-8 py-3 rounded font-semibold transition-all duration-300">
                {t("gallerySection.button")}
              </button>
            </Link>
          </div>
        </div>
      </section>

      {/* Services Section - Full Width Images */}
      <section className="py-20 px-4 bg-white">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            viewport={{ once: true, amount: 0.3 }}
            className="text-center mb-16"
          >
            <span className="text-[#C97A3C] text-sm font-semibold tracking-wider uppercase mb-3 block">
            {t("servicesSection.tagline")}
          </span>
          <h2 className="text-4xl font-bold text-[#5A3825] mb-4">
            {t("servicesSection.title")}
          </h2>
          <p className="text-gray-600 text-lg max-w-2xl mx-auto">
            {t("servicesSection.description")}
          </p>
          </motion.div>
        
          <div className="grid md:grid-cols-3 gap-8">
      {services.map((service, idx) => (
        <motion.div
          key={idx}
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: idx * 0.05 }}
          viewport={{ once: true, amount: 0.2 }}
          className="bg-white rounded-lg overflow-hidden shadow-lg hover:shadow-xl transition-all duration-300 group"
        >
          <div className="relative h-56 overflow-hidden">
            <Image
              src={service.img}
              alt={service.title}
              fill
              className="object-cover group-hover:scale-110 transition-transform duration-500"
              loading="lazy"
            />
            <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent" />
          </div>
          <div className="p-6">
            <h3 className="text-2xl text-center font-bold text-spiritual-green mb-3">
              {service.title}
            </h3>
            <p className="text-gray-600 text-center leading-relaxed">{service.desc}</p>
          </div>
        </motion.div>
      ))}
    </div>
        </div>
      </section>

      {/* Full Width Image Section */}
      <section className="relative h-[400px] md:h-[500px] overflow-hidden">
        <Image
          src="/images/carrying.jpeg"
          alt="Temple Devotees"
          fill
          className="object-cover"
          loading="lazy"
        />
        <div className="absolute inset-0 bg-black/50" />
        <div className="relative h-full flex items-center justify-center px-4">
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            viewport={{ once: true, amount: 0.3 }}
            className="text-center text-white max-w-3xl"
          >
           <h2 className="text-3xl md:text-5xl font-bold mb-6">
  {t("communitySection.title")}
</h2>
<p className="text-xl text-gray-100 mb-8">
  {t("communitySection.desc")}
</p>
          </motion.div>
        </div>
      </section>

      {/* Donation CTA */}
      <section className="py-20 bg-white">
      <div className="max-w-4xl mx-auto px-4 text-center">
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          viewport={{ once: true, amount: 0.3 }}
        >
          <span className="text-[#C97A3C] text-sm font-semibold tracking-wider uppercase mb-3 block">
            {t("donation.tagline")}
          </span>
          <h2 className="text-4xl font-bold mb-6 text-[#5A3825]">
            {t("donation.title")}
          </h2>
          <p className="text-xl mb-8 text-gray-600 max-w-2xl mx-auto leading-relaxed">
            {t("donation.description")}
          </p>
          <button className="bg-[#C97A3C] hover:bg-[#B5682B] text-white px-10 py-4 rounded text-lg font-semibold transition-all duration-300 hover:scale-105 shadow-lg">
            {t("donation.button")}
          </button>
        </motion.div>
      </div>
    </section>

      <Footer />
    </div>
  );
}
