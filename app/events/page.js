"use client";
import MyNav from "@/components/MyNav";
import Footer from "@/components/Footer";
import ExpandableCardModal from "@/components/expandable-card-demo-grid";
import { useLanguage } from "@/contexts/LanguageContext";
import { getTranslation } from "@/lib/translations";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import Image from "next/image";
import { motion } from "framer-motion";

export default function Events() {
  const { language } = useLanguage();
  const t = (key) => getTranslation(language, key);

  const events = [
    {
      title: language === 'hi' ? "कुबेर जयंती" : "Kuber Jayanti",
      date: language === 'hi' ? "कार्तिक पूर्णिमा" : "Kartik Purnima",
      description: language === 'hi' 
        ? "भगवान कुबेर के जन्म का भव्य उत्सव। विशेष अभिषेकम, मंत्रोच्चार और प्रसाद वितरण।"
        : "Grand celebration of Lord Kuber's birth. Special abhishekam, vedic chanting, and prasad distribution.",
      image: "/images/kuberji/kuber-chowk-31.jpeg"
    },
    {
      title: language === 'hi' ? "धनतेरस पूजा" : "Dhanteras Pooja",
      date: language === 'hi' ? "कार्तिक कृष्ण त्रयोदशी" : "Kartik Krishna Trayodashi",
      description: language === 'hi'
        ? "धन और समृद्धि के लिए लक्ष्मी-कुबेर की संयुक्त पूजा। रात्रि आरती और विशेष हवन।"
        : "Combined Lakshmi-Kuber worship for wealth and prosperity. Evening aarti and special havan.",
      image: "/images/kalas.jpg"
    },
    {
      title: language === 'hi' ? "महा आरती" : "Maha Aarti",
      date: language === 'hi' ? "प्रतिदिन संध्या" : "Daily Evening",
      description: language === 'hi'
        ? "भव्य संध्या आरती पारंपरिक संगीत और दीप दान के साथ। सभी भक्त सादर आमंत्रित हैं।"
        : "Grand evening aarti with traditional music and lamp offerings. All devotees welcome.",
      image: "/images/temple/temple-night.jpeg"
    },
    {
      title: language === 'hi' ? "रुद्राभिषेक" : "Rudrabhishek",
      date: language === 'hi' ? "प्रत्येक सोमवार" : "Every Monday",
      description: language === 'hi'
        ? "भगवान शिव को समर्पित शक्तिशाली वैदिक अनुष्ठान। बाधा निवारण और आध्यात्मिक उन्नति।"
        : "Powerful vedic ritual dedicated to Lord Shiva. Obstacle removal and spiritual elevation.",
      image: "/images/milkbath2.jpeg"
    },
    {
      title: language === 'hi' ? "अन्नकूट महोत्सव" : "Annakoot Festival",
      date: language === 'hi' ? "गोवर्धन पूजा" : "Govardhan Puja",
      description: language === 'hi'
        ? "56 भोग का भव्य आयोजन। देवता को विशाल भोजन अर्पित और भक्तों में प्रसाद वितरण।"
        : "Grand offering of 56 bhog. Massive food offering to the deity and prasad distribution.",
      image: "/images/carrying.jpeg"
    },
    {
      title: language === 'hi' ? "वार्षिक भंडारा" : "Annual Bhandara",
      date: language === 'hi' ? "वर्ष में दो बार" : "Twice a Year",
      description: language === 'hi'
        ? "सभी भक्तों के लिए मुफ्त सामुदायिक भोजन। हजारों लोगों को परोसा जाता है।"
        : "Free community feast for all devotees. Thousands are served with devotion.",
      image: "/images/temple/front-temple.jpg"
    }
  ];

  return (
    <main className="bg-heritage-cream min-h-screen">
      <MyNav />
      
      {/* Header Section - Heritage Design */}
      <section className="relative py-20 px-4 bg-ivory border-b border-sandalwood/10">
        {/* Subtle Pattern */}
        <div className="absolute inset-0 opacity-[0.015]">
          <div className="w-full h-full" style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Ctext x='30' y='35' text-anchor='middle' font-size='24' fill='%238B4513'%3Eॐ%3C/text%3E%3C/svg%3E")`,
            backgroundSize: '60px 60px'
          }}></div>
        </div>

        {/* Language Switcher */}
        <div className="absolute top-6 right-6">
          <LanguageSwitcher />
        </div>

        <div className="relative max-w-4xl mx-auto text-center space-y-4">
          <h1 className="text-5xl md:text-6xl font-light text-deep-brown tracking-wide" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
            {language === 'hi' ? 'हमारे पवित्र उत्सव' : 'Sacred Celebrations'}
          </h1>
          <p className="text-lg text-incense font-light max-w-2xl mx-auto" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
            {language === 'hi' 
              ? 'आध्यात्मिक समारोहों और पारंपरिक अनुष्ठानों में हमारे साथ जुड़ें। सभी भक्त सादर आमंत्रित हैं।'
              : 'Join us in spiritual celebrations and traditional rituals. All devotees are cordially invited.'}
          </p>
        </div>
      </section>

      {/* Events Grid - Heritage Design */}
      <section className="py-16 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {events.map((event, idx) => (
              <motion.div 
                key={idx}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: idx * 0.05 }}
                viewport={{ once: true, amount: 0.2 }}
                className="bg-ivory border border-sandalwood/15 rounded-sm overflow-hidden shadow-sm hover:shadow-md transition-all duration-300"
              >
                <div className="relative h-56">
                  <Image
                    src={event.image}
                    alt={event.title}
                    fill
                    className="object-cover"
                    onError={(e) => {
                      e.target.src = '/images/temple/temple.jpg';
                    }}
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-deep-brown/60 to-transparent" />
                  <div className="absolute bottom-4 left-4 right-4">
                    <h3 className="text-ivory text-xl font-light mb-1" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
                      {event.title}
                    </h3>
                    <p className="text-ivory/90 text-sm font-light" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                      {event.date}
                    </p>
                  </div>
                </div>
                <div className="p-6">
                  <p className="text-incense font-light leading-relaxed" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                    {event.description}
                  </p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Call to Action */}
      <section className="py-16 px-4 bg-sandalwood/5 border-t border-sandalwood/10">
        <div className="max-w-3xl mx-auto text-center space-y-6">
          <h2 className="text-3xl md:text-4xl font-light text-deep-brown" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
            {language === 'hi' ? 'उत्सवों में भाग लें' : 'Participate in Celebrations'}
          </h2>
          <p className="text-incense font-light" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
            {language === 'hi'
              ? 'हमारे विशेष कार्यक्रमों और दैनिक अनुष्ठानों में भाग लेने के लिए आज ही पूजा बुक करें।'
              : 'Book your pooja today to participate in our special events and daily rituals.'}
          </p>
          <a href="/aarti-pooja">
            <button className="bg-sandalwood text-ivory px-8 py-3 rounded-sm font-light transition-all duration-300 hover:bg-deep-brown border border-sandalwood shadow-sm" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
              {language === 'hi' ? 'पूजा बुक करें' : 'Book Pooja'}
            </button>
          </a>
        </div>
      </section>

      <Footer />
    </main>
  );
}