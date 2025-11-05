"use client";

import MyNav from "@/components/MyNav";
import Footer from "@/components/Footer";
import { MapPin, Phone, Mail, Clock } from 'lucide-react';
import { motion } from 'framer-motion';
import { useLanguage } from "@/contexts/LanguageContext";
import { getTranslation } from "@/lib/translations";
import LanguageSwitcher from "@/components/LanguageSwitcher";

export default function Contact() {
  const { language } = useLanguage();
  const t = (key) => getTranslation(language, key);

  return (
    <div className="bg-heritage-cream min-h-screen">
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
            {language === 'hi' ? 'संपर्क करें' : 'Contact Us'}
          </h1>
          <p className="text-lg text-incense font-light max-w-2xl mx-auto" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
            {language === 'hi' 
              ? 'हम आपकी पूछताछ का स्वागत करते हैं और आपको हमारे मंदिर समुदाय से जोड़ने में मदद करने के लिए उत्सुक हैं।'
              : 'We welcome your inquiries and look forward to helping you connect with our temple community.'}
          </p>
        </div>
      </section>

      {/* Contact Section - Heritage Design */}
      <section className="py-16 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="grid lg:grid-cols-2 gap-12">
            
            {/* Contact Information */}
            <motion.div 
              initial={{ opacity: 0, x: -20 }}
              whileInView={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5 }}
              viewport={{ once: true, amount: 0.3 }}
              className="space-y-6"
            >
              <div className="bg-ivory border border-sandalwood/15 rounded-sm p-8 shadow-sm">
                <h3 className="text-2xl font-light text-deep-brown mb-8" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
                  {language === 'hi' ? 'संपर्क जानकारी' : 'Contact Information'}
                </h3>
                <div className="space-y-6">
                  <div className="flex items-start space-x-4">
                    <div className="bg-sandalwood/10 p-3 rounded-sm">
                      <Mail className="h-5 w-5 text-sandalwood" />
                    </div>
                    <div>
                      <h4 className="font-light text-deep-brown mb-1" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                        {language === 'hi' ? 'ईमेल' : 'Email'}
                      </h4>
                      <p className="text-incense font-light">info@kuberjitemple.org</p>
                    </div>
                  </div>
                  <div className="flex items-start space-x-4">
                    <div className="bg-sandalwood/10 p-3 rounded-sm">
                      <Phone className="h-5 w-5 text-sandalwood" />
                    </div>
                    <div>
                      <h4 className="font-light text-deep-brown mb-1" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                        {language === 'hi' ? 'फोन' : 'Phone'}
                      </h4>
                      <p className="text-incense font-light">+91 12345 67890</p>
                    </div>
                  </div>
                  <div className="flex items-start space-x-4">
                    <div className="bg-sandalwood/10 p-3 rounded-sm">
                      <MapPin className="h-5 w-5 text-sandalwood" />
                    </div>
                    <div>
                      <h4 className="font-light text-deep-brown mb-1" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                        {language === 'hi' ? 'पता' : 'Address'}
                      </h4>
                      <p className="text-incense font-light">
                        {language === 'hi' ? 'पांडुकेश्वर' : 'Pandukeshwar'}
                        <br />
                        {language === 'hi' ? 'जोशीमठ, उत्तराखंड 246443' : 'Joshimath, UK 246443'}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start space-x-4">
                    <div className="bg-sandalwood/10 p-3 rounded-sm">
                      <Clock className="h-5 w-5 text-sandalwood" />
                    </div>
                    <div>
                      <h4 className="font-light text-deep-brown mb-1" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                        {language === 'hi' ? 'मंदिर समय' : 'Temple Hours'}
                      </h4>
                      <p className="text-incense font-light text-sm">
                        {language === 'hi' ? 'सोमवार - शुक्रवार: सुबह 7:00 - दोपहर 12:00, शाम 5:00 - रात 8:00' : 'Monday - Friday: 7:00 AM - 12:00 PM, 5:00 PM - 8:00 PM'}
                        <br />
                        {language === 'hi' ? 'शनिवार: सुबह 7:00 - दोपहर 12:00, शाम 4:00 - रात 9:00' : 'Saturday: 7:00 AM - 12:00 PM, 4:00 PM - 9:00 PM'}
                        <br />
                        {language === 'hi' ? 'रविवार: सुबह 7:00 - रात 9:00' : 'Sunday: 7:00 AM - 9:00 PM'}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-sandalwood border border-sandalwood rounded-sm p-8 text-ivory shadow-sm">
                <h4 className="text-xl font-light mb-4" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
                  {language === 'hi' ? 'दर्शन के लिए तैयार?' : 'Ready to Visit?'}
                </h4>
                <p className="mb-6 font-light leading-relaxed opacity-95" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                  {language === 'hi'
                    ? 'चाहे आप मार्गदर्शन चाहने वाले आध्यात्मिक साधक हों या हमारे उद्देश्य में योगदान देना चाहते हों, हम आपसे सुनना पसंद करेंगे।'
                    : "Whether you're a spiritual seeker looking for guidance or someone who wants to contribute to our cause, we'd love to hear from you."}
                </p>
                <a href="/aarti-pooja">
                  <button className="bg-ivory text-sandalwood px-6 py-3 rounded-sm font-light hover:bg-heritage-bg transition-all duration-300 border border-ivory" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
                    {language === 'hi' ? 'यात्रा की योजना बनाएं' : 'Plan Your Visit'}
                  </button>
                </a>
              </div>
            </motion.div>

            {/* Contact Form */}
            <motion.div 
              initial={{ opacity: 0, x: 30 }}
              whileInView={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6 }}
              viewport={{ once: true }}
              className="bg-ivory border border-sandalwood/15 rounded-sm p-8 shadow-sm"
            >
              <h3 className="text-2xl font-light text-deep-brown mb-8" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}>
                {language === 'hi' ? 'हमें संदेश भेजें' : 'Send us a Message'}
              </h3>
              <form className="space-y-6">
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-light text-deep-brown mb-2" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                      {language === 'hi' ? 'पहला नाम' : 'First Name'}
                    </label>
                    <input 
                      type="text"
                      placeholder={language === 'hi' ? 'आपका पहला नाम' : 'Your first name'}
                      className="w-full px-4 py-3 border border-sandalwood/20 rounded-sm focus:outline-none focus:ring-1 focus:ring-sandalwood transition-all bg-heritage-bg/30 text-deep-brown"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-light text-deep-brown mb-2" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                      {language === 'hi' ? 'अंतिम नाम' : 'Last Name'}
                    </label>
                    <input 
                      type="text"
                      placeholder={language === 'hi' ? 'आपका अंतिम नाम' : 'Your last name'}
                      className="w-full px-4 py-3 border border-sandalwood/20 rounded-sm focus:outline-none focus:ring-1 focus:ring-sandalwood transition-all bg-heritage-bg/30 text-deep-brown"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-light text-deep-brown mb-2" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                    {language === 'hi' ? 'ईमेल' : 'Email'}
                  </label>
                  <input 
                    type="email"
                    placeholder={language === 'hi' ? 'आपका.ईमेल@उदाहरण.com' : 'your.email@example.com'}
                    className="w-full px-4 py-3 border border-sandalwood/20 rounded-sm focus:outline-none focus:ring-1 focus:ring-sandalwood transition-all bg-heritage-bg/30 text-deep-brown"
                  />
                </div>
                <div>
                  <label className="block text-sm font-light text-deep-brown mb-2" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                    {language === 'hi' ? 'फोन' : 'Phone'}
                  </label>
                  <input 
                    type="tel"
                    placeholder="+91 12345 43210"
                    className="w-full px-4 py-3 border border-sandalwood/20 rounded-sm focus:outline-none focus:ring-1 focus:ring-sandalwood transition-all bg-heritage-bg/30 text-deep-brown"
                  />
                </div>
                <div>
                  <label className="block text-sm font-light text-deep-brown mb-2" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                    {language === 'hi' ? 'विषय' : 'Subject'}
                  </label>
                  <input 
                    type="text"
                    placeholder={language === 'hi' ? 'हम आपकी कैसे मदद कर सकते हैं?' : 'How can we help you?'}
                    className="w-full px-4 py-3 border border-sandalwood/20 rounded-sm focus:outline-none focus:ring-1 focus:ring-sandalwood transition-all bg-heritage-bg/30 text-deep-brown"
                  />
                </div>
                <div>
                  <label className="block text-sm font-light text-deep-brown mb-2" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                    {language === 'hi' ? 'संदेश' : 'Message'}
                  </label>
                  <textarea
                    placeholder={language === 'hi' ? 'अपनी पूछताछ के बारे में और बताएं...' : 'Tell us more about your inquiry...'}
                    className="w-full px-4 py-3 border border-sandalwood/20 rounded-sm focus:outline-none focus:ring-1 focus:ring-sandalwood transition-all bg-heritage-bg/30 text-deep-brown min-h-[120px]"
                  ></textarea>
                </div>
                <button 
                  type="submit"
                  className="w-full bg-sandalwood text-ivory px-6 py-3 rounded-sm font-light border border-sandalwood hover:bg-deep-brown transition-all duration-300" 
                  style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'Cormorant Garamond, serif' }}
                >
                  {language === 'hi' ? 'संदेश भेजें' : 'Send Message'}
                </button>
              </form>
            </motion.div>
          </div>
        </div>
      </section>

      <Footer/>
    </div>
  );
}
