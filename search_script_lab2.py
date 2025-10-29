import idautils
import idaapi
import idc

OPCODES = {
    "call esp": b"\xff\xd4",  # call esp
    "jmp esp": b"\xff\xe4",  # jmp esp
    "call eax": b"\xff\xd0",  # call eax
    "jmp eax": b"\xff\xe0",  # jmp eax
    "call ebx": b"\xff\xd3",  # call ebx
    "jmp ebx": b"\xff\xe3",  # jmp ebx
    "call ecx": b"\xff\xd1",  # call ecx
    "jmp ecx": b"\xff\xe1",  # jmp ecx
    "call edx": b"\xff\xd2",  # call edx
    "jmp edx": b"\xff\xe2",  # jmp edx
    "call edi": b"\xff\xd7",  # call edi
    "jmp edi": b"\xff\xe7",  # jmp edi
    "call esi": b"\xff\xd6",  # call esi
    "jmp esi": b"\xff\xe6",  # jmp esi
}


def find_opcodes():
    result = {}

    for seg in idautils.Segments():
        seg_start = idc.get_segm_start(seg)
        seg_end = idc.get_segm_end(seg)
        current_address = seg_start

        while current_address < seg_end:
            for instr_name, opcode in OPCODES.items():
                if idc.get_bytes(current_address, len(opcode)) == opcode:
                    if instr_name not in result:
                        result[instr_name] = []
                    result[instr_name].append(current_address)
            current_address = idc.next_head(current_address, seg_end)

    return result


def print_report(title, instructions_dict):
    print(f'\n{title}')
    print('_' * 60)

    if not instructions_dict:
        print("No instructions found")
        return

    for instruction, addresses in instructions_dict.items():
        print(f'\nInstruction: {instruction}')
        print('Addresses:')
        for ea in addresses:
            print(f'  0x{ea:X}')


if __name__ == "__main__":
    found_instructions = find_opcodes()
    print_report('FOUND INSTRUCTIONS (JMP/CALL REGISTER)', found_instructions)