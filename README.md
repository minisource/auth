https://docs.simplified.fr/Public/Deployment/deploy

1. add organization: http://localhost:8000/organizations/organization_uaontk
2. add new provider for sms: http://localhost:8000/providers
3. create application - remember to remove captcha
4. in application choose custom jwt and above that add name filed

## 🧪 سناریو: "سیستم مدیریت کاربران برای اپلیکیشن من"

### 🔧 پیش‌نیازها:

1. Casdoor روی سرور نصب شده (یا لوکال ران شده)
2. پنل مدیریت Casdoor در دسترسه (localhost:8000 یا آدرس سرورت)

---

## 🪜 مرحله ۱: ساخت Organization

**هدف**: تعریف محدوده‌ای برای کاربران اپلیکیشن

* وارد پنل Casdoor شو → بخش `Organizations`
* یک Organization جدید بساز به نام `my-org`

---

## 🪜 مرحله ۲: ساخت Application

**هدف**: تعریف اپلیکیشن خودت برای ورود کاربران

* برو به بخش `Applications` → دکمه "Add"
* پر کن:

  * **Name:** `my-app`
  * **Display Name:** `My App`
  * **Organization:** `my-org`
  * **Redirect URLs:** `http://localhost:3000/callback` (یا آدرس frontendت)
  * **Enable password login:** ✔️
  * **Enable signup:** ✔️
  * **Enable JWT token:** ✔️
* بعد از ذخیره، `Client ID` و `Client Secret` رو یادداشت کن ✅

---

## 🪜 مرحله ۳: ساخت Provider (اختیاری)

**هدف**: اگر بخوای ورود با Google یا GitHub داشته باشی

* برو به بخش `Providers` → Add
* مثلاً `Google` انتخاب کن و کلیدها رو وارد کن
* این provider رو در تنظیمات application فعال کن

---

## 🪜 مرحله ۴: ساخت Role و Permission

**هدف**: تفکیک دسترسی‌ها

1. **Role بساز**:

   * در بخش `Roles` → Add
   * Name: `admin`, `user` (هرچی نیاز داری)

2. **Permission تعریف کن**:

   * بخش `Permissions` → Add
   * مثال:

     * Resource: `data:*`
     * Action: `read`, `write`
     * Roles: `admin`

3. **Policy بساز** (یا این تنظیمات رو تو همون permission وارد کن)

---

## 🪜 مرحله ۵: ساخت یوزر تستی (اختیاری)

**هدف**: تست ورود و نقش

* برو `Users` → Add
* Name: `ebrahim`
* Email و Password بده
* Organization: `my-org`
* نقش `admin` رو بهش بده

---

## 🪜 مرحله ۶: ورود به سیستم

**مسیر ورود:**

```
https://<casdoor-domain>/login/oauth/authorize
  ?client_id=xxx
  &response_type=code
  &redirect_uri=http://localhost:3000/callback
  &scope=read
  &state=xyz
```

**Backend شما باید این `code` رو با `/api/login/oauth/access_token` به JWT تبدیل کنه.**

---

## 🪜 مرحله ۷: استفاده از JWT در Backend

**بعد از login موفق:**

* Casdoor بهت یک **JWT Token** می‌ده
* این توکن شامل اطلاعات مثل:

  * username
  * roles
  * organization
  * exp (انقضا)

**در Backend:**
تو هر ریکوئست، این توکن رو در `Authorization: Bearer <token>` می‌فرستی
و اون‌جا بررسی می‌کنی کاربر مجاز هست یا نه.

---

## 💡 مثال نهایی: جریان ورود

1. Frontend کاربر رو می‌فرسته به URL لاگین Casdoor
2. کاربر لاگین می‌کنه → به frontend برمی‌گرده با `code`
3. Frontend یا Backend این code رو به access\_token تبدیل می‌کنه
4. JWT رو ذخیره می‌کنی و ازش برای API استفاده می‌کنی

---

## ✅ ابزارهای کمکی:

* Casdoor JS SDK برای frontend (React, Vue, ...)
* Casdoor Go SDK, Node SDK برای backend
* REST API کامل برای همه کارها

---

اگه بخوای این سناریو رو برای مثلاً یک پروژه Go یا ASP.NET Core یا Python پیاده‌سازی کنیم، بگو راهنمای کاملشو برات می‌نویسم.
همچنین اگه بخوای بدونی چطور JWT رو validate کنیم سمت سرور، اونم بگو.
