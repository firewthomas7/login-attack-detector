# Login Attack Detector

A lightweight Python tool that detects **brute-force** and **credential-stuffing** attacks against web application login pages by analysing login logs, then produces alerts and an IP blocklist.

## Problem
Attackers constantly guess passwords or reuse leaked credentials against login pages. Small organisations rarely have monitoring in place, so account takeovers go unnoticed until damage is done.

## What it detects
| Alert type | Meaning |
|---|---|
| BRUTE_FORCE | Many failed logins from one IP (default: 10 within 5 minutes) |
| CREDENTIAL_STUFFING | One IP failing against many different usernames (default: 8 within 5 minutes) |
| SUCCESS_AFTER_FAILURES | A successful login after repeated failures on the same account (possible takeover) |

## Project files
| File | Purpose |
|---|---|
| `generate_logs.py` | Creates safe, synthetic login logs plus an answer key (no real systems are attacked) |
| `detector.py` | The detection tool; outputs `alerts.csv` and `blocklist.txt` |
| `evaluate.py` | Measures precision, recall and detection delay against the answer key |

## Requirements
Python 3.8 or newer. No external packages needed.

## How to run
```powershell
python generate_logs.py
python detector.py
python evaluate.py
```
Optional settings: `python detector.py --window 3600 --bf 10 --cs 8 --sa 5`

## Results (synthetic dataset: 904 login events, 8 attacker IPs)
| Time window | Precision | Recall | Avg. detection delay |
|---|---|---|---|
| 5 minutes (default) | 100% | 75% (6/8) | 19.5 s |
| 60 minutes | 100% | 100% (8/8) | 284.6 s |

## Limitations
- Low-and-slow attacks (one guess every 2 minutes) are missed with a short window.
- A longer window catches them but alerts later and may raise false alarms on busy shared IPs.
- Attackers using many IPs (distributed attacks) are not yet correlated.
- Tested on synthetic data only; real logs may need a different parser.

## Ethical note
All data is synthetic. This tool is for defensive purposes only.