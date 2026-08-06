'use client';

import { useEffect, useState } from 'react';
import { useTheme } from 'next-themes';
import { Languages } from 'lucide-react';
import { Button, ModeToggle } from '@minisource/ui';
import { useLang, useT } from '@/shared/i18n/LanguageProvider';

/**
 * Client-only gate.
 * Renders nothing on the server so the SSR payload and first client render
 * are identical (empty). After hydration the real controls appear.
 */
function ClientOnly({ children }: { children: React.ReactNode }) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    // Return an invisible placeholder that occupies the same visual space
    // so the layout does not jump once the controls mount.
    return <div className="h-9 w-[4.5rem]" aria-hidden="true" />;
  }

  return children;
}

export function HeaderControls() {
  const { lang, toggleLanguage } = useLang();
  const { t } = useT();
  const { theme, setTheme } = useTheme();

  return (
    <ClientOnly>
      <div className="flex items-center gap-2">
        <ModeToggle theme={theme} onToggle={(th) => setTheme(th)} />
        <Button
          variant="ghost"
          size="sm"
          onClick={toggleLanguage}
          title={lang === 'fa' ? t('header.lang.toEn') : t('header.lang.toFa')}
          className="gap-1.5 text-xs font-medium"
        >
          <Languages className="h-4 w-4" />
          <span className="hidden sm:inline">{lang === 'fa' ? 'Fa' : 'En'}</span>
        </Button>
      </div>
    </ClientOnly>
  );
}
