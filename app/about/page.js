"use client";
import React from "react";
import Image from "next/image";
import MyNav from "@/components/MyNav";
import Footer from "@/components/Footer";
import { motion } from "framer-motion";
import { useLanguage } from "@/contexts/LanguageContext";
import { getTranslation } from "@/lib/translations";
import LanguageSwitcher from "@/components/LanguageSwitcher";

export default function About() {
  const { language } = useLanguage();
  const t = (key) => getTranslation(language, key);

  const deities = [
    {
      name: { en: "Kuber Bhandari", hi: "कुबेर भंडारी" },
      role: { en: "God of Wealth", hi: "धन के देवता" },
      lineage: { en: "Kamdi Thok (Panwar)", hi: "कामडी ठोक (पंवार)" },
      desc: { 
        en: "Kuber Bhandari, the divine treasurer of the gods, is the main deity of Pandukeshwar. He is chiefly worshipped by the Kamdi Thok.",
        hi: "कुबेर भंडारी, देवताओं के दिव्य कोषाध्यक्ष, पांडुकेश्वर के मुख्य देवता हैं। उनकी मुख्य रूप से कामडी ठोक द्वारा पूजा की जाती है।"
      },
      img: "/images/kuberji/kuberji2.jpeg",
    },
    {
      name: { en: "Ghantakarna", hi: "घंटाकर्ण" },
      role: { en: "Kshetrapal (Protector)", hi: "क्षेत्रपाल (रक्षक)" },
      lineage: { en: "Bhandari Thok", hi: "भंडारी ठोक" },
      desc: { 
        en: "Ghantakarna Devta stands as the vigilant protector of Pandukeshwar, safeguarding the region and its sacred grounds.",
        hi: "घंटाकर्ण देवता पांडुकेश्वर के सतर्क रक्षक के रूप में खड़े हैं, क्षेत्र और उसके पवित्र स्थानों की रक्षा करते हुए।"
      },
      img: "/images/ghantakran.jpeg",
    },
    {
      name: { en: "Nanda Devi", hi: "नंदा देवी" },
      role: { en: "Goddess of Bliss", hi: "आनंद की देवी" },
      lineage: { en: "Bhatt & Mehta Thok", hi: "भट्ट और मेहता ठोक" },
      desc: { 
        en: "Nanda Devi is venerated as the compassionate Mother Goddess of Pandukeshwar. The Bhatt and Mehta Thoks are her primary devotees.",
        hi: "नंदा देवी पांडुकेश्वर की करुणामय माता देवी के रूप में पूजी जाती हैं। भट्ट और मेहता ठोक उनके प्रमुख भक्त हैं।"
      },
      img: "/images/deities/nanda-devi.jpg",
    },
    {
      name: { en: "Vishwakarma", hi: "विश्वकर्मा" },
      role: { en: "Divine Architect", hi: "दिव्य शिल्पकार" },
      lineage: { en: "Universal Worship", hi: "सार्वभौमिक पूजा" },
      desc: { 
        en: "Lord Vishwakarma, the celestial craftsman, is revered for his creative powers and blessings.",
        hi: "भगवान विश्वकर्मा, दिव्य शिल्पकार, अपनी रचनात्मक शक्तियों के लिए पूजनीय हैं।"
      },
      img: "/images/deities/vishwakarma.jpg",
    },
    {
      name: { en: "Laatu Devta", hi: "लाटू देवता" },
      role: { en: "Local Guardian Deity", hi: "स्थानीय संरक्षक देवता" },
      lineage: { en: "Village Protector", hi: "गाँव के रक्षक" },
      desc: { 
        en: "Laatu Devta is considered a fierce protective spirit deity, invoked for safeguarding the community.",
        hi: "लाटू देवता एक उग्र और सुरक्षात्मक आत्मा देवता माने जाते हैं, समुदाय की सुरक्षा के लिए आह्वान किए जाते हैं।"
      },
      img: "/images/deities/laatudevta.jpg",
    },
  ];

  const festivals = [
    {
      name: { en: "Makar Sankranti", hi: "मकर संक्रांति" },
      desc: { 
        en: "The first Gaadu of the year, marking the start of the divine cycle and invoking prosperity.",
        hi: "वर्ष की पहली गाडू, दिव्य चक्र की शुरुआत और समृद्धि का आह्वान।"
      },
      img: "/images/festivals/makar-sankranti.jpg",
    },
    {
      name: { en: "Vasant Panchami", hi: "वसंत पंचमी" },
      desc: { 
        en: "Celebrates the onset of spring and the day when the opening date of Badrinath Dham is decided.",
        hi: "वसंत के आगमन का उत्सव और वह दिन जब बद्रीनाथ धाम के खुलने की तिथि तय की जाती है।"
      },
      img: "/images/festivals/vasant-panchami.jpg",
    },
    {
      name: { en: "Baisakhi", hi: "बैसाखी" },
      desc: { 
        en: "Marks the opening of the sacred Kapaath (gates) of Badrinath Temple, symbolizing renewal and abundance.",
        hi: "बद्रीनाथ मंदिर के पवित्र कपाट के खुलने को चिह्नित करता है, नवीनीकरण और प्रचुरता का प्रतीक।"
      },
      img: "/images/festivals/baisakhi.jpg",
    },
    {
      name: { en: "Ashtami Gaadu", hi: "अष्टमी गाडू" },
      desc: { 
        en: "An inner village ritual symbolizing purity, devotion, and renewal of divine energy, held at the BAAMNI village.",
        hi: "बामनी गांव में आयोजित एक आंतरिक गांव अनुष्ठान, पवित्रता, भक्ति और दिव्य ऊर्जा के नवीनीकरण का प्रतीक।"
      },
      img: "/images/festivals/ashtami.jpg",
    },
    {
      name: { en: "Baawan Dwadasi", hi: "बावन द्वादशी" },
      desc: { 
        en: "The final and most revered Gaadu of the year, performed inside the Badrinath temple sanctum.",
        hi: "वर्ष की अंतिम और सबसे पूजनीय गाडू, बद्रीनाथ मंदिर गर्भगृह के अंदर की जाती है।"
      },
      img: "/images/festivals/baawan-dwadasi.jpg",
    },
  ];

  return (
    <div className="bg-heritage-cream cursor-default select-none min-h-screen">
      <MyNav />

      {/* Hero Section - Heritage Design */}
      <section className="relative py-16 px-4 bg-ivory border-b border-sandalwood/10">
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

        <div className="relative max-w-6xl mx-auto">
          <div className="flex flex-col md:flex-row gap-12 items-center">
            <motion.div
              initial={{ opacity: 0, x: -30 }}
              whileInView={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5 }}
              viewport={{ once: true, amount: 0.3 }}
              className="md:w-1/2"
            >
              <Image
                src="/images/sitting-2.jpeg"
                alt="Pandukeshwar Temple"
                className="rounded-sm shadow-sm"
                width={600}
                height={600}
              />
            </motion.div>
            <motion.div
              initial={{ opacity: 0, x: 30 }}
              whileInView={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5 }}
              viewport={{ once: true, amount: 0.3 }}
              className="md:w-1/2 space-y-4"
            >
              <h1 className="text-4xl md:text-5xl font-light text-deep-brown tracking-wide" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
                {language === 'hi' ? 'पांडुकेश्वर के बारे में' : 'About Pandukeshwar'}
              </h1>
              <p className="text-lg text-incense font-light leading-relaxed" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                {language === 'hi' 
                  ? 'शक्तिशाली हिमालय के बीच स्थित, पांडुकेश्वर चमोली जिले, उत्तराखंड में अलकनंदा नदी के पास एक पवित्र गाँव है। यह भगवान कुबेर के शीतकालीन निवास के रूप में जाना जाता है और भगवान बद्रीनाथ, पौराणिक कथाओं और प्राचीन अनुष्ठानों से गहरे संबंध रखता है।'
                  : 'Nestled amidst the mighty Himalayas, Pandukeshwar is a sacred village near the Alaknanda River in Chamoli district, Uttarakhand. It is known as the winter abode of Lord Kuber and holds deep ties to Lord Badrinath, mythology, and ancient rituals that continue to this day.'}
              </p>
            </motion.div>
          </div>
        </div>
      </section>

      {/* Gods Section - Heritage Design */}
      <section className="py-16 px-4">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-4xl md:text-5xl font-light text-center text-deep-brown mb-12 tracking-wide" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
            {language === 'hi' ? 'पांडुकेश्वर के देवता' : 'Deities of Pandukeshwar'}
          </h1>

          <div className="grid md:grid-cols-3 gap-8">
            {deities.map((god, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: idx * 0.05 }}
                viewport={{ once: true, amount: 0.2 }}
                className="bg-ivory border border-sandalwood/15 rounded-sm overflow-hidden shadow-sm hover:shadow-md transition-all duration-300"
              >
                <div className="relative h-64">
                  <Image
                    src={god.img}
                    alt={god.name[language]}
                    fill
                    className="object-cover"
                  />
                </div>
                <div className="p-6 space-y-2">
                  <h2 className="text-2xl font-light text-deep-brown" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
                    {god.name[language]}
                  </h2>
                  <p className="text-sandalwood font-light text-sm" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>{god.role[language]}</p>
                  <p className="text-stone text-xs font-light italic" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                    {language === 'hi' ? 'वंश: ' : 'Lineage: '}{god.lineage[language]}
                  </p>
                  <p className="text-incense font-light leading-relaxed" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>{god.desc[language]}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Festivals & Gaadu Section - Heritage Design */}
      <section className="py-16 px-4 bg-sandalwood/5 border-t border-sandalwood/10">
        <div className="max-w-6xl mx-auto">
          <h1 className="text-4xl md:text-5xl font-light text-center text-deep-brown mb-8 tracking-wide" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
            {language === 'hi' ? 'उत्सव और पवित्र गाडू परंपरा' : 'Festivals & The Sacred Gaadu Tradition'}
          </h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            viewport={{ once: true, amount: 0.3 }}
            className="text-lg text-incense font-light text-center max-w-4xl mx-auto mb-12" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}
          >
            {language === 'hi'
              ? 'एक अनूठा अनुष्ठान जिसे "गाडू" — या स्व-अभिषेक — के रूप में जाना जाता है, वर्ष में पांच बार होता है, जहां चुने हुए व्यक्तियों को दिव्य का अवतार माना जाता है।'
              : 'A unique ritual known as "Gaadu" — or self-abhishek — takes place five times a year, where chosen individuals are believed to embody the divine.'}
          </motion.p>

          {/* Timeline */}
          <div className="space-y-12">
            {festivals.map((fest, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: i * 0.05 }}
                viewport={{ once: true, amount: 0.2 }}
                className={`flex flex-col ${i % 2 === 0 ? 'md:flex-row' : 'md:flex-row-reverse'} items-center gap-8`}
              >
                <div className="md:w-1/2">
                  <div className="relative h-64 rounded-sm overflow-hidden shadow-sm">
                    <Image
                      src={fest.img}
                      alt={fest.name[language]}
                      fill
                      className="object-cover"
                    />
                  </div>
                </div>
                <div className="md:w-1/2 bg-ivory border border-sandalwood/15 p-8 rounded-sm shadow-sm">
                  <h2 className="text-3xl font-light text-deep-brown mb-4" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
                    {fest.name[language]}
                  </h2>
                  <p className="text-incense font-light leading-relaxed" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                    {fest.desc[language]}
                  </p>
                </div>
              </motion.div>
            ))}
          </div>

          <p className="text-center mt-12 text-lg text-incense font-light" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
            {language === 'hi'
              ? 'पांच गाडुओं में से तीन पांडुकेश्वर में और दो बद्रीनाथ धाम के गर्भगृह में होती हैं।'
              : 'Out of the five Gaadus, three take place in Pandukeshwar and two within the sanctum of Badrinath Dham.'}
          </p>
        </div>
      </section>

      <Footer />
    </div>
  );
}
