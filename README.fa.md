<div align="center">

# اسکنر SNI-Spoofing

**این پروژه لیستی از کانفیگ‌ها را تبدیل و اسکن می‌کند تا کانفیگ‌هایی که برای SNI-Spoofing مناسب هستند را پیدا کند.**

انواع کانفیگ پشتیبانی شده: trojan, vless  
بقیه ی نوع ها درنظر گرفته نمیشوند.

---

</div>

## راهنمای سریع

1. آخرین نسخه [SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing/releases/latest) را دانلود کنید و اجرا کنید.
2. آخرین نسخه این برنامه، [SNI-Spoofing-Scanner](https://github.com/zmn-hamid/sni-spoofing-scanner/releases/latest) را دانلود کنید اما اجرا نکنید.
3. فایل `config.example.json` را کپی کنید و نام آن را به `config.json` تغییر دهید.
4. (اختیاری) در صورت نیاز فایل کانفیگ را ویرایش کنید. پورت و آدرس SNI-Spoofing باید مطابقت داشته باشند.
5. فایل `configs.txt` بسازید و تمام کانفیگ‌های خود را داخل آن قرار دهید. هر کانفیگ در یک خط.
7. اسکنر را اجرا کنید. بعد از اتمام، فایلی به نام `working_configs.txt` ایجاد خواهد شد.

### نصب دستی

گزینه ۱:
```bash
go install github.com/matinsenpai/senpaiscanner/cmd/senpaiscanner@latest
```

گزینه ۲:
1. Golang را نصب کنید.
2. این ریپازیتوری را کلون کنید.
3. دستور `go mod download` را اجرا کنید.
4. حالا می‌توانید یکی از کارهای زیر را انجام دهید:
    - اجرا: `go run .`
    - ساخت: `go build -o sni-spoofing-scanner.exe`
    - نصب: `go install`

## چجوری کار میکنه؟

ابتدا کانفیگ‌های داده‌شده را به یک کانفیگ قابل استفاده برای SNI Spoofing تبدیل می‌کند (با جایگزین کردن IP و پورت). سپس، به تعداد دفعاتی که در فایل `config.json` مشخص کرده‌اید، کانفیگ را تست پینگ می‌کند. برای تست کانفیگ‌ها از هسته Xray استفاده می‌شود. تنها کافی است قبل از اجرای برنامه، خودِ SNI Spoofing را راه‌اندازی کرده باشید.

## قدردانی

- [Xray-core by XTLS](https://github.com/xtls/xray-core)

## لایسنس

[MIT License](./LICENSE)