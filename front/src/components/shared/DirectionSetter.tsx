'use client';

import { useLayoutEffect } from 'react';
import { useLang } from '@/shared/i18n/LanguageProvider';

/**
 * Sets `dir` and `lang` on <html> based on the current language.
 * Runs as a layout effect to avoid a visible direction flicker after hydration.
 */
export function DirectionSetter() {
  const { lang } = useLang();

  useLayoutEffect(() => {
    const html = document.documentElement;
    html.dir = lang === 'fa' ? 'rtl' : 'ltr';
    html.lang = lang;
  }, [lang]);

  return null;
}
