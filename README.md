![Logo](admin/byd.png)

# ioBroker.byd

[![NPM version](https://img.shields.io/npm/v/iobroker.byd.svg)](https://www.npmjs.com/package/iobroker.byd)
[![Downloads](https://img.shields.io/npm/dm/iobroker.byd.svg)](https://www.npmjs.com/package/iobroker.byd)
![Number of Installations](https://iobroker.live/badges/byd-installed.svg)
![Current version in stable repository](https://iobroker.live/badges/byd-stable.svg)

[![NPM](https://nodei.co/npm/iobroker.byd.png?downloads=true)](https://nodei.co/npm/iobroker.byd/)

**Tests:** ![Test and Release](https://github.com/TA2k/ioBroker.byd/workflows/Test%20and%20Release/badge.svg)

## byd adapter for ioBroker

iobroker Adapter for BYD cars based on https://github.com/Niek/BYD-re

## Charging and Connection States

The adapter reads vehicle status from the BYD Realtime API. Not all state fields work reliably across all vehicle models.

### Working States (from Realtime API)

| Field         | Value | Meaning                                  |
|---------------|-------|------------------------------------------|
| `chargeState` | 0     | Not connected                            |
| `chargeState` | 1     | Charging                                 |
| `chargeState` | 15    | Gun connected (plugged in, not charging) |

### Unreliable States

The following fields from the Realtime API return `-1` (Unknown) on some vehicle models and should not be relied upon:

| Field          | Issue                              |
|----------------|------------------------------------|
| `chargingState` | Always returns -1 on some models  |
| `connectState`  | Always returns -1 on some models  |

**Note:** Home Assistant's BYD integration uses `chargingState` for charging detection, which does not work for all vehicles. This adapter uses `chargeState` instead, which appears to be more reliable.

### Derived States

Based on `chargeState`, the adapter provides:
- **isCharging**: `chargeState === 1`
- **isPluggedIn**: `chargeState === 1 || chargeState === 15`

## Changelog

<!--
    Placeholder for the next version (at the beginning of the line):
    ### **WORK IN PROGRESS**
-->

### **WORK IN PROGRESS**

- (TA2k) initial release

## License

MIT License

Copyright (c) 2026 TA2k <tombox2020@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
