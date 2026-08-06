/**
 * Bilingual translations for the Auth Admin Frontend.
 */

import { resolveLanguage } from './language';

type Lang = 'fa' | 'en';

const translations: Record<string, Record<Lang, string>> = {
  // ── Navigation ────────────────────────────────────
  'nav.dashboard': { fa: 'داشبورد', en: 'Dashboard' },
  'nav.identity': { fa: 'مدیریت هویت', en: 'Identity Management' },
  'nav.users': { fa: 'کاربران', en: 'Users' },
  'nav.sessions': { fa: 'نشست‌های فعال', en: 'Active Sessions' },
  'nav.accessControl': { fa: 'کنترل دسترسی', en: 'Access Control' },
  'nav.roles': { fa: 'نقش‌ها', en: 'Roles' },
  'nav.permissions': { fa: 'مجوزها', en: 'Permissions' },
  'nav.tenancy': { fa: 'چندمستاجری', en: 'Tenancy' },
  'nav.tenants': { fa: 'مستاجران', en: 'Tenants' },
  'nav.integrations': { fa: 'یکپارچه‌سازی', en: 'Integrations' },
  'nav.serviceClients': { fa: 'کلاینت‌های سرویس', en: 'Service Clients' },
  'nav.oauthProviders': { fa: 'ارائه‌دهندگان OAuth', en: 'OAuth Providers' },
  'nav.system': { fa: 'سیستم', en: 'System' },
  'nav.settings': { fa: 'تنظیمات', en: 'Settings' },
  'nav.loginLogs': { fa: 'گزارش ورودها', en: 'Login Logs' },
  'nav.tools': { fa: 'ابزارها', en: 'Tools' },
  'nav.apiLab': { fa: 'آزمایشگاه API', en: 'API Test Lab' },
  'nav.tokenTools': { fa: 'سنجش و اعتبارسنجی توکن', en: 'Token Validation Tools' },
  'nav.serviceAuth': { fa: 'احراز هویت سرویس به سرویس', en: 'Service Auth' },
  'nav.profile': { fa: 'پروفایل کاربر', en: 'Profile' },
  'nav.myProfile': { fa: 'پروفایل من', en: 'My Profile' },
  'nav.linkedAccounts': { fa: 'حساب‌های متصل', en: 'Linked Accounts' },
  'nav.mySessions': { fa: 'نشست‌های من', en: 'My Sessions' },
  'nav.logout': { fa: 'خروج از حساب', en: 'Logout' },
  'nav.globalAdmin': { fa: 'مدیریت کل سیستم', en: 'Global Administration' },
  'nav.currentTenant': { fa: 'مستاجر فعال', en: 'Current Tenant' },

  // ── Header & layout ───────────────────────────────
  'header.admin': { fa: 'مدیر سیستم', en: 'System Admin' },
  'header.logout': { fa: 'خروج', en: 'Logout' },
  'header.theme.light': { fa: 'تغییر به حالت روشن', en: 'Switch to light mode' },
  'header.theme.dark': { fa: 'تغییر به حالت تاریک', en: 'Switch to dark mode' },
  'header.lang.toEn': { fa: 'Switch to English', en: 'Switch to English' },
  'header.lang.toFa': { fa: 'تغییر به فارسی', en: 'تغییر به فارسی' },

  // ── Auth states ───────────────────────────────────
  'auth.checking': { fa: 'در حال بررسی احراز هویت...', en: 'Checking authentication...' },
  'auth.accessDenied': { fa: 'دسترسی غیرمجاز', en: 'Access Denied' },
  'auth.noPermission': {
    fa: 'شما مجوز دسترسی به این صفحه را ندارید.',
    en: "You don't have permission to access this page.",
  },
  'auth.goToDashboard': { fa: 'رفتن به داشبورد', en: 'Go to Dashboard' },

  // ── Dashboard ──────────────────────────────────────
  'dashboard.welcome': { fa: 'خوش آمدید', en: 'Welcome back' },
  'dashboard.tenantAdmin': { fa: 'مدیر مستاجر', en: 'Tenant Admin' },
  'dashboard.subtitle': {
    fa: 'مرکز عملیات و مدیریت امنیت مینی‌سورس',
    en: 'MiniSource Auth Operations & Security Administration Center',
  },
  'dashboard.allTenants': { fa: 'همه مستاجران (سراسری)', en: 'All Tenants (Global)' },
  'dashboard.refresh': { fa: 'به‌روزرسانی', en: 'Refresh' },
  'dashboard.totalUsers': { fa: 'کل کاربران', en: 'Total Users' },
  'dashboard.activeUsers': { fa: 'فعال', en: 'active' },
  'dashboard.lockedUsers': { fa: 'قفل‌شده', en: 'locked' },
  'dashboard.activeSessions': { fa: 'نشست‌های فعال', en: 'Active Sessions' },
  'dashboard.failed24h': { fa: 'تلاش ناموفق (۲۴ ساعت)', en: 'failed attempts (24h)' },
  'dashboard.tenantsOrgs': { fa: 'مستاجران و سازمان‌ها', en: 'Tenants & Orgs' },
  'dashboard.serviceClients': { fa: 'کلاینت‌های سرویس', en: 'Service Clients' },
  'dashboard.accessControl': { fa: 'کنترل دسترسی', en: 'Access Control' },
  'dashboard.oauthProviders': { fa: 'ارائه‌دهندگان OAuth', en: 'OAuth Providers' },
  'dashboard.rolesPermissions': { fa: 'نقش‌ها / مجوزها', en: 'Roles / Permissions' },
  'dashboard.securityTitle': { fa: 'نمای کلی امنیت و ریسک', en: 'Security & Risk Overview' },
  'dashboard.securityHealthy': { fa: 'وضعیت امنیت سالم است', en: 'Security Status Healthy' },
  'dashboard.securityHealthyDesc': {
    fa: 'تهدید امنیتی فعال، حساب قفل‌شده یا موج ورود غیرعادی شناسایی نشد.',
    en: 'No active security threats, locked accounts, or abnormal login spikes detected.',
  },
  'dashboard.failedLoginsAlert': { fa: 'تلاش ناموفق ورود شناسایی شد', en: 'Failed Logins Detected' },
  'dashboard.lockedUsersAlert': { fa: 'حساب‌های قفل‌شده', en: 'Locked User Accounts' },
  'dashboard.unverifiedEmailsAlert': { fa: 'ایمیل‌های تأییدنشده', en: 'Unverified Email Addresses' },
  'dashboard.reviewLoginLogs': { fa: 'بررسی گزارش ورودها', en: 'Review Login Logs' },
  'dashboard.manageUsers': { fa: 'مدیریت کاربران', en: 'Manage Users' },
  'dashboard.inspectUsers': { fa: 'بررسی کاربران', en: 'Inspect Users' },
  'dashboard.sessionsTitle': { fa: 'نشست‌های فعال کاربران', en: 'Active User Sessions' },
  'dashboard.viewAllSessions': { fa: 'مشاهده همه نشست‌ها', en: 'View All Sessions' },
  'dashboard.sessionsDesc': {
    fa: 'نشست‌های احراز هویت‌شده زنده و توکن‌های OAuth فعال',
    en: 'Live authenticated client sessions and active OAuth tokens',
  },
  'dashboard.sessionIp': { fa: 'شناسه نشست / IP', en: 'Session ID / IP' },
  'dashboard.userAgent': { fa: 'مرورگر کلاینت', en: 'Client User-Agent' },
  'dashboard.status': { fa: 'وضعیت', en: 'Status' },
  'dashboard.lastActive': { fa: 'آخرین فعالیت', en: 'Last Active' },
  'dashboard.active': { fa: 'فعال', en: 'Active' },
  'dashboard.expired': { fa: 'منقضی', en: 'Expired' },
  'dashboard.noSessions': { fa: 'نشست فعال از راه دوری یافت نشد.', en: 'No active remote sessions found.' },
  'dashboard.systemHealth': { fa: 'سلامت سیستم', en: 'System Health' },
  'dashboard.healthDesc': {
    fa: 'وضعیت عملیاتی سرویس‌های زیرساخت احراز هویت',
    en: 'Operational status of core auth infrastructure services',
  },
  'dashboard.quickActions': { fa: 'اقدامات سریع عملیاتی', en: 'Quick Operational Actions' },
  'dashboard.quickActionsDesc': {
    fa: 'وظایف پرتکرار مدیریتی بر اساس مجوزهای شما',
    en: 'Frequent administration tasks based on your permissions',
  },
  'dashboard.auditFeed': { fa: 'خوراک ممیزی اخیر', en: 'Recent Audit Feed' },
  'dashboard.logs': { fa: 'گزارش‌ها', en: 'Logs' },
  'dashboard.noActivity': { fa: 'فعالیت سیستمی اخیری ثبت نشده است.', en: 'No recent system activities recorded.' },
  'dashboard.retryAccess': { fa: 'تلاش مجدد', en: 'Retry Access' },
  'dashboard.unavailableTitle': {
    fa: 'سرویس بک‌اند احراز هویت در دسترس نیست',
    en: 'Auth Backend Service Unavailable',
  },
  'dashboard.passwordWarningTitle': {
    fa: 'هشدار امنیتی: رمز عبور پیش‌فرض فعال است',
    en: 'Security Alert: Default Password Active',
  },
  'dashboard.passwordWarningDesc': {
    fa: 'حساب شما در حال استفاده از رمز عبور پیش‌فرض مدیر سیستم است. این یک ریسک امنیتی جدی است. لطفاً فوراً رمز عبور خود را تغییر دهید.',
    en: 'Your account is currently using the default system administrator password. This is a severe security risk. Please change your password immediately.',
  },
  'dashboard.changePassword': { fa: 'تغییر رمز عبور', en: 'Change Password' },
  'dashboard.dismiss': { fa: 'رد کردن', en: 'Dismiss' },
};

export function translateKey(key: string, lang: Lang): string {
  const entry = translations[key];
  if (!entry) {
    // Humanize fallback key instead of showing raw "nav.tokenTools"
    const lastPart = key.split('.').pop() || key;
    const humanized = lastPart.replace(/([A-Z])/g, ' $1').replace(/^./, (str) => str.toUpperCase()).trim();
    return humanized;
  }
  return entry[lang] ?? entry.en ?? key;
}

export function t(key: string): string {
  return translateKey(key, resolveLanguage());
}

export { translations };
