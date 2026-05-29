# SNI-Spoofing Scanner

This project scans a list of configs to find the ones that can be used with SNI-Spoofing.

Supported config types: trojan, vless

## Attribution

This project works closely with [SNI-Spoofing by Patterniha](https://github.com/patterniha/SNI-Spoofing)

### Installation

1. Download the [SNI-Spoofing app](https://github.com/patterniha/SNI-Spoofing/releases).
2. Download the latest release of SNI-Scanner app (this project).

If you don't find your operating system, do the manual installation:
1. Install Golang.
2. Clone this repo.
3. Run `go mod download`
4. Now you can either:
    - Run: `go run .`
    - Build: `go build -o sni-scanner.exe`
    - Install: `go install`

### Usage

1. Run the SNI-Spoofing app
2. Copy `config.example.json` and rename it to `config.json`.
3. (Optional) Modify the config file if you need to.
4. Make a `configs.txt` file and put all your configs there. Each config in one line.
5. Run the app. After it's finished, it will create a file called `working_configs.txt`.
You can use them now.

## License

[MIT License](./LICENSE)