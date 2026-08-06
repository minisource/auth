/**
 * Language resolver for the Auth Admin Frontend.
 * Resolved language is sent via X-Language and Accept-Language headers.
 */

type SupportedLanguage = 'fa' | 'en';

/**
 * Normalizes a raw language string to "fa" or "en".
 */
export function normalizeLanguage(raw: string): SupportedLanguage {
  if (!raw) return 'fa';

  const cleaned = raw.trim().toLowerCase().replace(/_/g, '-');
  const primaryTag = cleaned.split('-')[0];

  if (primaryTag === 'fa') return 'fa';
  if (primaryTag === 'en') return 'en';

  return 'fa';
}

/**
 * Resolves the current user language:
 * 1. localStorage preference
 * 2. Browser language
 * 3. Fallback to "fa"
 */
export function resolveLanguage(): SupportedLanguage {
  if (typeof window !== 'undefined') {
    const saved = localStorage.getItem('X-Language');
    if (saved) return normalizeLanguage(saved);

    if (navigator.language) {
      return normalizeLanguage(navigator.language);
    }
  }

  return 'fa';
}

export function setLanguage(lang: SupportedLanguage): void {
  if (typeof window !== 'undefined') {
    localStorage.setItem('X-Language', lang);
  }
}

export function getAcceptLanguageHeader(lang: SupportedLanguage): string {
  if (lang === 'fa') return 'fa-IR,fa;q=0.9,en;q=0.8';
  return 'en-US,en;q=0.9,fa;q=0.8';
}

export function getLanguageHeader(lang: SupportedLanguage): string {
  return lang;
}
