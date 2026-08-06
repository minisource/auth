'use client';

import { useState, type ComponentType } from 'react';
import { useLang } from '@/shared/i18n/LanguageProvider';
import {
  Apple,
  ChevronDown,
  ChevronUp,
  Chrome,
  ExternalLink,
  Facebook,
  Github,
  HelpCircle,
  KeyRound,
  Lock,
  Settings2,
  ShieldCheck,
} from 'lucide-react';

type Lang = 'fa' | 'en';

interface FieldGuide {
  label: Record<Lang, string>;
  hint: Record<Lang, string>;
}

interface ProviderGuide {
  icon: ComponentType<{ className?: string }>;
  site?: { label: Record<Lang, string>; url: string };
  steps: Record<Lang, string[]>;
  fields: {
    clientId: FieldGuide;
    clientSecret: FieldGuide;
    redirectUrl?: FieldGuide;
    scopes?: FieldGuide;
  };
  note?: Record<Lang, string>;
}

const GUIDES: Record<string, ProviderGuide> = {
  google: {
    icon: Chrome,
    site: {
      label: { fa: 'Google Cloud Console', en: 'Google Cloud Console' },
      url: 'https://console.cloud.google.com/apis/credentials',
    },
    steps: {
      fa: [
        'وارد Google Cloud Console شوید و یک پروژه انتخاب یا بسازید.',
        'از منوی کناری به APIs & Services → Credentials بروید.',
        'روی Create Credentials → OAuth client ID کلیک کنید.',
        'نوع برنامه را Web application انتخاب کنید.',
        'در Authorized redirect URIs آدرس بازگشت را اضافه کنید و روی Create بزنید.',
      ],
      en: [
        'Open Google Cloud Console and pick or create a project.',
        'In the side menu, go to APIs & Services → Credentials.',
        'Click Create Credentials → OAuth client ID.',
        'Choose Web application as the application type.',
        'Add your redirect URL under Authorized redirect URIs and click Create.',
      ],
    },
    fields: {
      clientId: {
        label: { fa: 'Client ID', en: 'Client ID' },
        hint: {
          fa: 'همانجا، کنار نام کلاینت OAuth که ساختید نمایش داده میشود.',
          en: 'Shown right next to the OAuth client you created.',
        },
      },
      clientSecret: {
        label: { fa: 'Client Secret', en: 'Client Secret' },
        hint: {
          fa: 'همزمان با Client ID ساخته میشود و فقط یک بار نمایش داده میشود. اگر آن را ندارید: روی همان کلاینت کلیک کنید و Download JSON یا Reset secret را بزنید.',
          en: 'Created together with the Client ID and shown only once. If you lost it: open the client and use Download JSON or Reset secret.',
        },
      },
      redirectUrl: {
        label: { fa: 'Redirect URL', en: 'Redirect URL' },
        hint: {
          fa: 'باید دقیقاً با Authorized redirect URI که در گوگل ثبت کردید یکی باشد.',
          en: 'Must exactly match the Authorized redirect URI you registered on Google.',
        },
      },
      scopes: {
        label: { fa: 'Scopes', en: 'Scopes' },
        hint: { fa: 'پیش‌فرض: openid email profile', en: 'Default: openid email profile' },
      },
    },
    note: {
      fa: 'اگر گوگل فقط یک Client ID به شما داده و خبری از Secret نیست، احتمالاً یک API key ساخته‌اید یا نوع کلاینت را اشتباه انتخاب کرده‌اید (مثلاً Android/iOS). برای ورود با گوگل باید OAuth client ID از نوع Web application بسازید — در این حالت هم Client ID و هم Client Secret صادر می‌شود.',
      en: 'If Google only gave you a Client ID with no secret, you probably created an API key or picked the wrong client type (e.g. Android/iOS). For Google login you need an OAuth client ID of type Web application — it issues both a Client ID and a Client Secret.',
    },
  },
  github: {
    icon: Github,
    site: {
      label: { fa: 'GitHub Developer Settings', en: 'GitHub Developer Settings' },
      url: 'https://github.com/settings/developers',
    },
    steps: {
      fa: [
        'به GitHub Developer Settings بروید.',
        'روی New OAuth App بزنید.',
        'Homepage URL و Authorization callback URL را پر کنید و Register application را بزنید.',
      ],
      en: [
        'Open GitHub Developer Settings.',
        'Click New OAuth App.',
        'Fill in Homepage URL and Authorization callback URL, then click Register application.',
      ],
    },
    fields: {
      clientId: {
        label: { fa: 'Client ID', en: 'Client ID' },
        hint: { fa: 'در صفحه تنظیمات اپلیکیشن، بخش Client ID.', en: 'On the app settings page, in the Client ID section.' },
      },
      clientSecret: {
        label: { fa: 'Client Secret', en: 'Client Secret' },
        hint: {
          fa: 'روی Generate a new client secret بزنید — فقط یک بار نمایش داده می‌شود.',
          en: 'Click Generate a new client secret — it is shown only once.',
        },
      },
      redirectUrl: {
        label: { fa: 'Redirect URL', en: 'Redirect URL' },
        hint: {
          fa: 'Authorization callback URL در گیت‌هاب باید برابر Redirect URL این فرم باشد.',
          en: 'The Authorization callback URL on GitHub must equal the Redirect URL in this form.',
        },
      },
    },
  },
  facebook: {
    icon: Facebook,
    site: {
      label: { fa: 'Facebook for Developers', en: 'Facebook for Developers' },
      url: 'https://developers.facebook.com/apps',
    },
    steps: {
      fa: [
        'وارد Facebook for Developers شوید و یک Create App بسازید.',
        'محصول Facebook Login را به برنامه اضافه کنید.',
        'از منوی سمت چپ به Settings → Basic بروید.',
      ],
      en: [
        'Open Facebook for Developers and create an app.',
        'Add the Facebook Login product to the app.',
        'Go to Settings → Basic in the left menu.',
      ],
    },
    fields: {
      clientId: {
        label: { fa: 'App ID', en: 'App ID' },
        hint: { fa: 'در تنظیمات Basic، بخش App ID.', en: 'In Basic settings, in the App ID section.' },
      },
      clientSecret: {
        label: { fa: 'App Secret', en: 'App Secret' },
        hint: { fa: 'در تنظیمات Basic — دکمه Show را بزنید.', en: 'In Basic settings — click Show.' },
      },
      redirectUrl: {
        label: { fa: 'Redirect URL', en: 'Redirect URL' },
        hint: {
          fa: 'در Facebook Login → Settings بخش Valid OAuth Redirect URIs.',
          en: 'Under Facebook Login → Settings, in the Valid OAuth Redirect URIs section.',
        },
      },
    },
  },
  apple: {
    icon: Apple,
    site: {
      label: { fa: 'Apple Developer', en: 'Apple Developer' },
      url: 'https://developer.apple.com/account',
    },
    steps: {
      fa: [
        'وارد Apple Developer شوید و به Certificates, IDs & Profiles بروید.',
        'یک App ID با قابلیت Sign in with Apple بسازید.',
        'یک Services ID و یک Key (برای Sign in with Apple) بسازید.',
      ],
      en: [
        'Open Apple Developer and go to Certificates, IDs & Profiles.',
        'Register an App ID with the Sign in with Apple capability.',
        'Create a Services ID and a Key for Sign in with Apple.',
      ],
    },
    fields: {
      clientId: {
        label: { fa: 'Client ID', en: 'Client ID' },
        hint: { fa: 'شناسه Services ID که ساختید.', en: 'The Services ID identifier you created.' },
      },
      clientSecret: {
        label: { fa: 'Client Secret', en: 'Client Secret' },
        hint: {
          fa: 'در اپل Secret یک رشته ثابت نیست؛ باید با کلید خصوصی (Key) و Team ID یک JWT بسازید. این بخش پیچیده‌تر است.',
          en: 'On Apple the secret is not a static string; you must build a JWT using the private Key and Team ID. This part is more involved.',
        },
      },
      redirectUrl: {
        label: { fa: 'Redirect URL', en: 'Redirect URL' },
        hint: {
          fa: 'در تنظیمات Sign in with Apple، فیلد Return URL را برابر Redirect URL این فرم بگذارید.',
          en: 'In Sign in with Apple settings, set Return URL to match the Redirect URL in this form.',
        },
      },
    },
  },
  custom: {
    icon: Settings2,
    steps: {
      fa: [
        'برای هر سرویس OAuth2 سفارشی، یک OAuth App در پنل همان سرویس بسازید.',
        'مقادیر Auth URL، Token URL و User Info URL را از مستندات همان سرویس بردارید.',
      ],
      en: [
        "For any custom OAuth2 service, create an OAuth App in that service's dashboard.",
        "Take the Auth URL, Token URL and User Info URL values from that service's documentation.",
      ],
    },
    fields: {
      clientId: {
        label: { fa: 'Client ID', en: 'Client ID' },
        hint: { fa: 'از پنل سرویس مورد نظر.', en: "From the service's dashboard." },
      },
      clientSecret: {
        label: { fa: 'Client Secret', en: 'Client Secret' },
        hint: { fa: 'از پنل سرویس مورد نظر.', en: "From the service's dashboard." },
      },
      redirectUrl: {
        label: { fa: 'Redirect URL', en: 'Redirect URL' },
        hint: {
          fa: 'همان آدرس بازگشتی که در سرویس ثبت می‌کنید.',
          en: 'The callback URL you register on the service.',
        },
      },
    },
  },
};

export function CredentialsGuide({ selectedType }: { selectedType?: string }) {
  const { lang } = useLang();
  const [open, setOpen] = useState(true);

  const guide = selectedType ? GUIDES[selectedType] : undefined;
  const t = lang === 'fa' ? 'fa' : 'en';

  return (
    <div className="rounded-lg border bg-muted/30 p-3">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-2 text-sm font-medium text-foreground"
      >
        <span className="flex items-center gap-2">
          <HelpCircle className="h-4 w-4 text-muted-foreground" />
          {lang === 'fa' ? 'این مقادیر را از کجا بیاورم؟' : 'Where do I get these values?'}
        </span>
        {open ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
      </button>

      {open && (
        <div className="mt-3 space-y-3 text-sm">
          {!guide ? (
            <p className="text-muted-foreground">
              {lang === 'fa'
                ? 'ابتدا یک Type برای Provider انتخاب کنید تا راهنمای ثبت‌نام همان سرویس نمایش داده شود.'
                : 'Select a provider Type first to see registration instructions for that service.'}
            </p>
          ) : (
            <>
              {/* Provider header */}
              <div className="flex items-center gap-2">
                <guide.icon className="h-4 w-4 text-foreground" />
                <span className="font-semibold capitalize">{selectedType}</span>
                {guide.site && (
                  <a
                    href={guide.site.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                  >
                    {guide.site.label[t]}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                )}
              </div>

              {/* Steps */}
              <ol className="list-decimal space-y-1 ps-5 text-muted-foreground">
                {guide.steps[t].map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>

              {/* Field hints */}
              <div className="space-y-2">
                <FieldHint icon={KeyRound} field={guide.fields.clientId} t={t} />
                <FieldHint icon={Lock} field={guide.fields.clientSecret} t={t} />
                {guide.fields.redirectUrl && <FieldHint icon={ShieldCheck} field={guide.fields.redirectUrl} t={t} />}
                {guide.fields.scopes && <FieldHint icon={Settings2} field={guide.fields.scopes} t={t} />}
              </div>

              {/* Special note */}
              {guide.note && (
                <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-2.5 text-xs text-amber-700 dark:text-amber-400">
                  <span className="font-medium">{lang === 'fa' ? 'نکته:' : 'Note:'}</span> {guide.note[t]}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function FieldHint({ icon: Icon, field, t }: { icon: ComponentType<{ className?: string }>; field: FieldGuide; t: Lang }) {
  return (
    <div className="flex items-start gap-2">
      <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
      <p>
        <span className="font-medium">{field.label[t]}:</span>{' '}
        <span className="text-muted-foreground">{field.hint[t]}</span>
      </p>
    </div>
  );
}
