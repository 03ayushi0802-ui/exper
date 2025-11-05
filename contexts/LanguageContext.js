'use client';

import { createContext, useContext, useState, useEffect, useMemo, useCallback } from 'react';

const LanguageContext = createContext();

export function LanguageProvider({ children }) {
  const [language, setLanguage] = useState('en');
  const [isLoaded, setIsLoaded] = useState(false);

  useEffect(() => {
    // Load saved language preference
    const savedLang = localStorage.getItem('kuberji_language') || 'en';
    setLanguage(savedLang);
    setIsLoaded(true);
  }, []);

  const toggleLanguage = useCallback(() => {
    const newLang = language === 'en' ? 'hi' : 'en';
    setLanguage(newLang);
    localStorage.setItem('kuberji_language', newLang);
  }, [language]);

  const setLang = useCallback((lang) => {
    if (lang !== language) {
      setLanguage(lang);
      localStorage.setItem('kuberji_language', lang);
    }
  }, [language]);

  const value = useMemo(
    () => ({ language, toggleLanguage, setLang, isLoaded }),
    [language, toggleLanguage, setLang, isLoaded]
  );

  return (
    <LanguageContext.Provider value={value}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error('useLanguage must be used within LanguageProvider');
  }
  return context;
}
