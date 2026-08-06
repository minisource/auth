'use client';

import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import { resolveLanguage, setLanguage } from './language';
import { translateKey } from './translations';

type Lang = 'fa' | 'en';

interface LanguageContextValue {
  lang: Lang;
  toggleLanguage: () => void;
  setLang: (lang: Lang) => void;
  /** Whether the language has been resolved from client storage. False during SSR. */
  resolved: boolean;
}

const LanguageContext = createContext<LanguageContextValue>({
  lang: 'fa',
  toggleLanguage: () => {},
  setLang: () => {},
  resolved: false,
});

export function LanguageProvider({ children }: { children: ReactNode }) {
  // Always start with 'fa' during SSR to avoid hydration mismatch.
  // The actual saved language is resolved in the effect below.
  const [lang, setLangState] = useState<Lang>('fa');
  const [resolved, setResolved] = useState(false);

  // Sync with localStorage after hydration
  useEffect(() => {
    const detected = resolveLanguage();
    setLangState(detected);
    setResolved(true);
  }, []);

  const setLang = useCallback((newLang: Lang) => {
    setLangState(newLang);
    setLanguage(newLang);
  }, []);

  const toggleLanguage = useCallback(() => {
    setLangState((prev) => {
      const next = prev === 'fa' ? 'en' : 'fa';
      setLanguage(next);
      return next;
    });
  }, []);

  return (
    <LanguageContext.Provider value={{ lang, toggleLanguage, setLang, resolved }}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLang() {
  return useContext(LanguageContext);
}

export function useT() {
  const { lang } = useLang();
  const t = useCallback((key: string) => translateKey(key, lang), [lang]);
  return { t, lang };
}
