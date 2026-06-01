# Warp Scanner

Warp Scanner is a Python and Go-based Cloudflare WARP endpoint scanner with endpoint validation using AmneziaWG.

## Requirements

Place the following files in the same folder:

* warp_tester.py
* run.bat
* awg_verifier.exe (download it from the Releases page)
* Your WARP configuration file named `config.conf`

## Installation

Open a Command Prompt in the folder and install the required Python package:

```
pip install rich
```

## Usage

After installing the dependency, double-click `run.bat` to start the scanner.

The scanner will test endpoints and validate them using AmneziaWG.

## Notes

This project may still contain bugs and unfinished features. The code is relatively simple and can be modified easily. It was vibe coded with GPT-5.5 and DeepSeek.

## Additional Tool: test_awg_verifier.py

The repository also includes `test_awg_verifier.py`, which can be used to verify WARP connectivity for a list of specific endpoints.

Open the file in a text editor and modify the `ENDPOINTS` list:

```
ENDPOINTS = [
    "8.6.112.208:7281",
    "188.114.97.6:7281",
    "8.34.146.1:2371",
    ...
]
```

You can use AI tools to generate endpoint lists if needed.

To run the verifier, place `test_awg_verifier.py` and `awg_verifier.exe` in the same folder and execute:

```
python test_awg_verifier.py
```

The verifier provides more detailed and cleaner logging than `warp_tester.py`, but it does not scan for endpoints on its own. It only tests the endpoints that you provide in the `ENDPOINTS` list.
