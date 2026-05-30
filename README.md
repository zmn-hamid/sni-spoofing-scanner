<div align="center">

# SNI-Spoofing Scanner

**This project converts and scans a list of configs to find the ones that can be used for SNI-Spoofing.**

Supported config types: trojan, vless  
others will be ignored

[فارسی](./README.fa.md)

---

</div>

## Quick Start

1. Download the latest release of [SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing/releases/latest) and run it
2. Download the latest release of this app, [SNI-Spoofing-Scanner](https://github.com/zmn-hamid/sni-spoofing-scanner/releases/latest) but don't run it
3. Copy the `config.example.json` file and rename it to `config.json`.
4. (Optional) Modify the config file if you need to. The port and address of SNI-Spoofing must match.
5. Make a `configs.txt` file and put all your configs there. Each config in one line.
6. Run the scanner. After it's finished, it will create a file called `working_configs.txt`.

### Manual Installation

1. Install Golang.
2. Clone this repo.
3. Run `go mod download`
4. Now you can either:
    - Run: `go run .`
    - Build: `go build -o sni-spoofing-scanner.exe`
    - Install: `go install`

## How Does It Work

It will first conver the given configs to a conig that is usable for sni-spoofing 
(by replacing the ip and port), then it'll ping test the config as many times as 
you have defined in the `config.json` file. It uses xray core to test the configs. 
You just need to run sni-spoofing itself before starting the app.

## Attribution

- [Xray-core by XTLS](https://github.com/xtls/xray-core)

## License

[MIT License](./LICENSE)


