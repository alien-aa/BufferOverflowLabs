input_string = input("Введите строку: ")
padding_needed = (4 - (len(input_string) % 4)) % 4
padded_string = input_string + '\x00' * padding_needed
reversed_string = padded_string[::-1]
print("Перевёрнутая строка:", repr(reversed_string))
bytes_data = reversed_string.encode('utf-8')
hex_string = bytes_data.hex()
print("Hex:", hex_string)
print("Формат push XXXXXXXXh:")
for i in range(0, len(hex_string), 8):
    chunk = hex_string[i:i+8]
    print(f"push 0x{chunk}")
