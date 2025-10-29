# Базовый адрес kernel32
kernel32_base = 0x76030000

# Адреса функций
CreateProcessA = 0x76065150
ExitProcess = 0x76056a20

# Расчет смещений
offset_CreateProcessA = CreateProcessA - kernel32_base
offset_ExitProcess = ExitProcess - kernel32_base

print(f"CreateProcessA offset: 0x{offset_CreateProcessA:08X}")
print(f"ExitProcess offset: 0x{offset_ExitProcess:08X}")