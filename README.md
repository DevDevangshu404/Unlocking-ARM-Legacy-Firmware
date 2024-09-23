# Unlocking Legacy ARM Firmware: Brute Force Unicorn Rehosting and Protocol Reverse Engineering on Raspberry Pi Pico - Devangshu Mazumder

# Check more about it in my website: https://www.devangshumazumder.com/projects/content/rehost/rehostpi

## Project Overview

This project documents the reverse engineering of UART and SPI protocols on a Raspberry Pi Pico-based hardware security token, as well as rehosting a key firmware function using the Unicorn emulator. The goal was to recover the PIN required to unlock the device, which was successfully achieved through protocol analysis and PIN brute-forcing.

---

## Key Highlights

- **Protocol Reverse Engineering**: Successfully decoded UART and SPI communication using a logic analyzer to retrieve two flags.
- **Unicorn Rehosting**: Emulated the firmware, skipped unnecessary functions, and brute-forced the PIN (4919) using hooks in Unicorn.
- **Flags Retrieved**:
    - `sshs{0bf36248f395f54fe045f584205b1919}`
    - `sshs{7151eccf18521761a656d97a6f0851a}`
    - `sshs{8ea8549aff0b37a8d1f537c65aebfe55}`

---

## Tools and Technologies

- **Saleae Logic Analyzer**
- **Unicorn Emulator**
- **Ghidra**
- **Python**
- **Docker**

---

## Project Setup

### Clone the Repository

```bash
git clone https://github.com/DevDevangshu404/Unlocking-ARM-Legacy-Firmware.git
cd unlocking-ARM-Legacy-Firmware


```
### Build the Docker Image

```bash
docker build -t rehosting_project .

```

### Run the Project

```bash
docker run --rm rehosting_project

```

- **The script will emulate the firmware using Unicorn and run a brute-force attack to recover the correct PIN and flag.
