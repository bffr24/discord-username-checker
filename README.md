# Custom Discord Username Checker

Custom Discord username checker using residential proxies.

Author: bffr

## Requirements
- Python 3
- Tkinter (bundled with most Python installs)
- Packages in `requirements.txt`

## Setup
```bash
pip install -r requirements.txt
```

## Run
- Windows: run `run.bat`
- Any OS: `python main.py`

## Usage (UI)
- Webhooks: optional. Use separate webhooks for random and custom checks if desired.
- Proxies: one per line in `ip:port` or `user:pass@ip:port` format.
- Custom usernames: one per line.
- Random settings: length, numbers, special (`_` and `.`), optional prefix and position.
- Mode: custom only, random only, or both.
- Threads: per mode (1 to 50).
- Click Start to save `config.yaml` and begin checking.

## Examples
Proxies:
```
127.0.0.1:8080
user:pass@10.0.0.2:3128
```

Custom usernames:
```
bffr
test
mother
```
