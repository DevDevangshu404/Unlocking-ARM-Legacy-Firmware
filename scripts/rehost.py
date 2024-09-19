from unicorn import *
from unicorn.arm_const import *

# ASCII Art Header
print(
    r"""
  _   _       _                        ____             _         _____                    ____ ___ ____ ___
 | | | |_ __ (_) ___ ___  _ __ _ __   | __ ) _ __ _   _| |_ ___  |  ___|__  _ __ ___ ___  |  _ \_ _/ ___/ _ \
 | | | | '_ \| |/ __/ _ \| '__| '_ \  |  _ \| '__| | | | __/ _ \ | |_ / _ \| '__/ __/ _ \ | |_) | | |  | | | |
 | |_| | | | | | (_| (_) | |  | | | | | |_) | |  | |_| | ||  __/ |  _| (_) | | | (_|  __/ |  __/| | |__| |_| |
  \___/|_| |_|_|\___\___/|_|  |_| |_| |____/|_|   \__,_|\__\___| |_|  \___/|_|  \___\___| |_|  |___\____\___/
"""
)

test_data = {"pin": None, "found": False, "flag": None}


def read_string(uc, address):
    string = b""
    while True:
        char = uc.mem_read(address, 1)
        if char == b"\x00":
            break
        string += char
        address += 1
    try:
        return string.decode()
    except:
        return None


def hook_printf(uc):
    uc.reg_write(UC_ARM_REG_PC, 0x1000046A | 1)


def hook_instr_code(uc, address, size, user_data):

    if uc.reg_read(UC_ARM_REG_PC) == 0x10000466:
        hook_printf(uc)

    if uc.reg_read(UC_ARM_REG_PC) == 0x1000046E:
        hook_scanf(uc, user_data)

    if uc.reg_read(UC_ARM_REG_PC) == 0x10000476:
        hook_sleep_ms(uc)

    if uc.reg_read(UC_ARM_REG_PC) == 0x100004BA:
        hook_puts(uc)


def hook_scanf(uc, user_data):
    address = uc.reg_read(UC_ARM_REG_R1)
    uc.mem_write(address, user_data["pin"].to_bytes(2, "little"))
    uc.reg_write(UC_ARM_REG_R0, 1)
    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_PC) + 4 | 1)


def hook_sleep_ms(uc):
    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_PC) + 4 | 1)


def hook_puts(uc):
    string_ptr = uc.reg_read(UC_ARM_REG_R0)
    flag = read_string(uc, string_ptr)
    uc.reg_write(UC_ARM_REG_PC, 0x1100004BE | 1)
    if flag == None:
        print("{} : Invalid Flag".format(test_data["pin"]))
    else:
        print(f"PUTS: {flag}")
        test_data["flag"] = flag
        if "flag{" in flag or "sshs" in flag:
            test_data["flag"] = flag
            test_data["found"] = True


mu = unicorn.Uc(UC_ARCH_ARM, UC_MODE_THUMB)


with open("fw.bin", "rb") as f:
    firmware_data = f.read()
with open("sram.bin", "rb") as f:
    sram_data = f.read()
with open("rom.bin", "rb") as f:
    srom_data = f.read()


mu.mem_map(0x10000000, len(firmware_data))
mu.mem_map(0x20000000, len(sram_data))
mu.mem_map(0x0, len(srom_data))
mu.mem_write(0x10000000, firmware_data)
mu.mem_write(0x20000000, sram_data)
mu.mem_write(0x0, srom_data)


mu.reg_write(UC_ARM_REG_R0, 0x00000013)
mu.reg_write(UC_ARM_REG_R1, 0x00000000)
mu.reg_write(UC_ARM_REG_R2, 0x00000000)
mu.reg_write(UC_ARM_REG_R3, 0x00000003)
mu.reg_write(UC_ARM_REG_R4, 0x20041DE8)
mu.reg_write(UC_ARM_REG_R5, 0x1000D3D8)
mu.reg_write(UC_ARM_REG_R6, 0x1000D3D4)
mu.reg_write(UC_ARM_REG_SP, 0x20041DE0 | 1)
mu.reg_write(UC_ARM_REG_LR, 0x10000A93 | 1)
mu.reg_write(UC_ARM_REG_PC, 0x10000460 | 1)


def bruteforce_pin():
    try:
        for i in range(4900, 10000):
            test_data["pin"] = i
            mu.hook_add(UC_HOOK_CODE, hook_instr_code, test_data)
            mu.emu_start(0x10000460 | 1, until=0x100004C0)
            print("Emulation {} Completed!!".format(i))
            if test_data["found"] == True:
                print("flag found = {}".format(test_data["flag"]))
                break
    except UcError as e:
        print("Unicorn Error:", e)
        print("Error code:", e.errno)


bruteforce_pin()
