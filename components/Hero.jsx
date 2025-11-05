"use client";
import React from "react";
import Image from "next/image";
import { motion } from "framer-motion";
import { useLanguage } from "@/contexts/LanguageContext";
import { getTranslation } from "@/lib/translations";

export function Hero() {
  const { language } = useLanguage();
  const t = (key) => getTranslation(language, key);

  return (
    <section className="relative md:block mx-auto py-8 md:py-16">
      <motion.section 
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        viewport={{ once: true, amount: 0.2 }}
        className="relative w-full overflow-hidden"
      >
        {/* Foreground content */}
        <div className="relative z-10 flex items-center justify-center h-full px-4">
          <div className="section-card w-full max-w-6xl" data-section="about">
            <motion.h1 
              initial={{ opacity: 0, x: -20 }}
              whileInView={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              viewport={{ once: true }}
              className="text-4xl md:text-5xl font-bold text-spiritual-gold mb-6 mt-2 font-quicksand"
              style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}
            >
              {t('aboutHero.title')}
            </motion.h1>
            <div className="container flex flex-col md:flex-row mx-auto gap-8">
              <motion.div 
                initial={{ opacity: 0, x: -20 }}
                whileInView={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.5, delay: 0.2 }}
                viewport={{ once: true }}
                className="max-w-prose space-y-6"
              >
                <p className="font-medium md:text-lg text-spiritual-green leading-relaxed" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                  {t('aboutHero.paragraph1')}
                </p>

                <p className="font-medium md:text-lg text-spiritual-green leading-relaxed" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                  {t('aboutHero.paragraph2')}
                </p>

                <p className="font-medium md:text-lg text-spiritual-green leading-relaxed" style={{ fontFamily: language === 'hi' ? 'Noto Serif Devanagari, serif' : 'inherit' }}>
                  {t('aboutHero.paragraph3')}
                </p>
              </motion.div>
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                whileInView={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.5, delay: 0.3 }}
                viewport={{ once: true }}
              >
                <Image
                  src="/images/kuberji/kuberji1.jpeg"
                  alt="Kuberji Mandir Pandukeshwar"
                  className="rounded-3xl w-full max-w-xs h-auto image-hover-glow"
                  width={280}
                  height={320}
                  loading="lazy"
                />
              </motion.div>
            </div>
          </div>
        </div>
      </motion.section>
    </section>
  );
}

// {/* <section className="relative bg-primary md:h-screen">
//       <motion.div
//         initial={{ opacity: 0, y: 50 }}
//         whileInView={{ opacity: 1, y: 0 }}
//         transition={{ duration: 1.5, ease: "easeInOut" }}
//         viewport={{ once: true }}
//         className=" select-none cursor-default relative max-w-7xl my-auto mx-auto w-full"
//       >
//         <main className="md:mx-16 mx-2 my-auto bg-amber-100 rounded-xl">
//           <h1 className="text-4xl font-extrabold text-center text-primary mb-4 mt-4">About</h1>
//           <div className="flex flex-col items-center justify-center p-4">

//              <p className=" font-Manrope font-bold md:text-xl mt-8 text-primary">
//                 Lord Shri Badrinath's treasurer, Shri Kuber Bhandari, the
//                 treasurer of the gods, resides in this divine Kuber temple in
//                 Pandukeshwar during winters. It is near Yog Badri which is one
//                 of the Panch Badri.
//                 <br />
//                 In Vastu Shastra, the building or plot facing Ishan Mukha is
//                 compared to Kuber Dev's city Alkapuri, the remote Alkapuri is
//                 the origin of the Alaknanda river. Alkapuri is located at the
//                 base of the Balkunwar peak at an altitude of 4,600 meters above
//                 sea level near Badrinath in Chamoli district of Uttarakhand.
//               </p>
//           </div>
//         </main>

//         {/* Foreground content */}
//         <div className="flex flex-col  sm:flex-row items-center  mx-2 md:mx-16">
//           <div className="md:block  h-full">
//             <motion.div
//               className="relative z-10"
//               initial={{ opacity: 0, x: -50 }}
//               whileInView={{ opacity: 1, x: 0 }}
//               transition={{ duration: 2, ease: "easeInOut" }}
//               viewport={{ once: true }}
//             >

//               <p className=" font-Manrope font-bold md:text-xl mt-8 text-amber-100">
//                 Lord Shri Badrinath's treasurer, Shri Kuber Bhandari, the
//                 treasurer of the gods, resides in this divine Kuber temple in
//                 Pandukeshwar during winters. It is near Yog Badri which is one
//                 of the Panch Badri.
//                 <br />
//                 In Vastu Shastra, the building or plot facing Ishan Mukha is
//                 compared to Kuber Dev's city Alkapuri, the remote Alkapuri is
//                 the origin of the Alaknanda river. Alkapuri is located at the
//                 base of the Balkunwar peak at an altitude of 4,600 meters above
//                 sea level near Badrinath in Chamoli district of Uttarakhand.
//               </p>
//               <hr className="border-amber-100 border-2 mt-4 rounded-full"/>
//             </motion.div>
//           </div>
//         </div>
//       </motion.div>
//     </section> */}
