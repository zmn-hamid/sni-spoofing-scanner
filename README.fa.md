<div align="center">

# اسکنر SNI-Spoofing

**این پروژه لیستی از کانفیگ‌ها را اسکن می‌کند تا کانفیگ‌هایی که برای SNI-Spoofing مناسب هستند را پیدا کند.**

انواع کانفیگ پشتیبانی شده: trojan, vless

---

</div>

### راهنمای سریع

1. آخرین نسخه [SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing/releases/latest) را دانلود کنید و اجرا کنید.
2. آخرین نسخه این برنامه، [SNI-Spoofing-Scanner](https://github.com/zmn-hamid/sni-spoofing-scanner/releases/latest) را دانلود کنید اما اجرا نکنید.
3. فایل `config.example.json` را کپی کنید و نام آن را به `config.json` تغییر دهید.
4. (اختیاری) در صورت نیاز فایل کانفیگ را ویرایش کنید. پورت و آدرس SNI-Spoofing باید مطابقت داشته باشند.
5. فایل `configs.txt` بسازید و تمام کانفیگ‌های خود را داخل آن قرار دهید. هر کانفیگ در یک خط.
7. اسکنر را اجرا کنید. بعد از اتمام، فایلی به نام `working_configs.txt` ایجاد خواهد شد.

#### نصب دستی

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

### لایسنس

[MIT License](./LICENSE)