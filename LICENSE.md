# MIT License

**Copyright (c) 2026 Marek Wesołowski (WESMAR)**

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.**

---

## Scope of This License

The MIT License applies to the **source code** of this project:

- `x64/*.asm` — MASM x64 source modules
- `x64/*.inc` — include files (constants, globals)
- `x64/vg.rc` — resource script
- `x64/vg.manifest` — application manifest
- `build.ps1` — build automation script
- `tests/cli_test.ps1` — regression test suite
- `IcoBuilder/vg.ico` — base icon (ICO header)
- `README.md`, `LICENSE.md`, documentation

---

## Third-Party Component: `IcoBuilder/vg.sys`

**`vg.sys` is NOT covered by this license.**

`vg.sys` is a kernel-mode FSFilter Content Screener minifilter driver.
All rights to `vg.sys` belong to **PROMOSOFT CORPORATION**.

This binary was signed under a cross-signing certificate issued in 2014.
It is included in this repository solely to enable building and running VaultGuard
on supported Windows systems.

> The original vendor (PROMOSOFT CORPORATION) has been unreachable and their product
> has been discontinued for over a decade. This binary is redistributed in good faith
> for compatibility and preservation purposes. If you are a rights holder and object
> to this redistribution, please contact: **marek@wesolowski.eu.org**

The redistribution of `vg.sys` does not imply any claim of ownership or authorship
over the driver binary. Users are responsible for ensuring compliance with applicable
laws in their jurisdiction.

---

## Project Information

- **Project:** VaultGuard — kernel-backed folder protection for Windows
- **Author:** Marek Wesołowski (WESMAR)
- **Contact:** marek@wesolowski.eu.org
- **GitHub:** https://github.com/wesmar/VaultGuard
- **Platform:** Windows 11 x64
- **Language:** MASM x64 (pure native, no CRT)

---

*Copyright (c) 2026 Marek Wesołowski (WESMAR). Source code licensed under MIT License.*
