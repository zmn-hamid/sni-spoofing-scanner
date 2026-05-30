<div align="center">

# SNI-Spoofing Scanner

**This project scans a list of configs to find the ones that can be used for SNI-Spoofing.**

Supported config types: trojan, vless

[English](#english) • [فارسی](#فارسی)

---

</div>

## English

This project scans a list of configs to find the ones that can be used with SNI-Spoofing.

Supported config types: trojan, vless

### Quick Start

1. Download the latest release of [SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing/releases/latest) and run it
2. Download the latest release of this app, [SNI-Spoofing-Scanner](https://github.com/zmn-hamid/sni-spoofing-scanner/releases/latest) and run it
3. Run the SNI-Spoofing app
4. Copy the `config.example.json` file and rename it to `config.json`.
5. (Optional) Modify the config file if you need to. The port and address of SNI-Spoofing must match.
6. Make a `configs.txt` file and put all your configs there. Each config in one line.
7. Run the app. After it's finished, it will create a file called `working_configs.txt`.

#### Manual Installation

Option 1:
```
go install github.com/matinsenpai/senpaiscanner/cmd/senpaiscanner@latest
```

Option 2:
1. Install Golang.
2. Clone this repo.
3. Run `go mod download`
4. Now you can either:
    - Run: `go run .`
    - Build: `go build -o sni-spoofing-scanner.exe`
    - Install: `go install`

### License

[MIT License](./LICENSE)

## فارسی

این پروژه فهرستی از کانفیگ‌ها را اسکن می‌کند تا کانفیگ‌هایی را که قابلیت استفاده با SNI-Spoofing دارند پیدا کند.

انواع کانفیگ‌های پشتیبانی‌شده: `trojan`، `vless`

### شروع سریع

1. آخرین نسخه‌ی [SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing/releases/latest) را دانلود و اجرا کنید.
2. آخرین نسخه‌ی این برنامه، [SNI-Spoofing-Scanner](https://github.com/zmn-hamid/sni-spoofing-scanner/releases/latest) را دانلود و اجرا کنید.
3. برنامه‌ی SNI-Spoofing را اجرا کنید.
4. فایل `config.example.json` را کپی کرده و نام آن را به `config.json` تغییر دهید.
5. (اختیاری) در صورت نیاز فایل تنظیمات را ویرایش کنید. پورت و آدرس SNI-Spoofing باید با مقادیر این برنامه مطابقت داشته باشند.
6. فایلی با نام `configs.txt` ایجاد کرده و تمام کانفیگ‌های خود را در آن قرار دهید. هر کانفیگ باید در یک خط جداگانه باشد.
7. برنامه را اجرا کنید. پس از اتمام فرآیند، فایلی با نام `working_configs.txt` ایجاد خواهد شد.

#### نصب دستی

گزینه ۱:

```bash
go install github.com/matinsenpai/senpaiscanner/cmd/senpaiscanner@latest
```

گزینه ۲:

1. زبان برنامه‌نویسی Golang را نصب کنید.
2. این مخزن را Clone کنید.
3. دستور `go mod download` را اجرا کنید.
4. اکنون می‌توانید یکی از روش‌های زیر را انتخاب کنید:
    - اجرا: `go run .`
    - ساخت فایل اجرایی: `go build -o sni-spoofing-scanner.exe`
    - نصب: `go install`

### مجوز

[مجوز MIT](./LICENSE)