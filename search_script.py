import idc
import idautils
import idaapi


INPUT_FUNCTIONS = {
    'fgetc', 'fgets', 'fread', 'fscanf', 'getc', 'getchar', 'gets',
    'read', 'scanf', 'sscanf', 'vfscanf', 'vscanf', 'vsscanf',
    'getpass', 'cin'
}

UNSAFE_FUNCTIONS = {
    # Copying and concatenation
    'strcpy', 'strncpy', 'stpcpy', 'lstrcpy', 'StrCpy',
    'strcat', 'strncat', 'lstrcat', 'StrCat',
    'sprintf', 'vsprintf', 'snprintf', 'vsnprintf',
    'memcpy', 'memmove', 'memset', 'gets', 'strecpy', 'streadd', 'strtrns',
    # Format strings
    'printf', 'fprintf', 'vprintf', 'vfprintf',
    # Input/output
    'scanf', 'fscanf', 'sscanf', 'vscanf', 'vfscanf', 'vsscanf',
    'getpass', 'realpath', 'getwd', 'cin', '_splitpath', 'makepath'
}

def get_func_name(ea):
    """
    Return the function name at the given address, or a visible name if not a function.
    """
    name = idc.get_func_name(ea)
    if name:
        return name
    return idc.get_name(ea, idc.GN_VISIBLE)

def find_calls(target_funcs):
    """
    Find calls to functions from target_funcs (exact name match).
    Returns a dict: {function_name: [call_addresses]} (only for found functions).
    """
    result = {}
    for seg_start in idautils.Segments():
        for head in idautils.Heads(seg_start, idc.get_segm_end(seg_start)):
            mnem = idc.print_insn_mnem(head)
            if mnem in ('call', 'bl', 'jal'):  # x86/x64/ARM/MIPS
                operand_addr = idc.get_operand_value(head, 0)
                if operand_addr:
                    callee_name = get_func_name(operand_addr)
                    if callee_name in target_funcs:
                        if callee_name not in result:
                            result[callee_name] = []
                        result[callee_name].append(head)
    return result

def print_report(title, calls_dict):
    print(f'\n{title}')
    print('_'*60)
    for func, addrs in calls_dict.items():
        print('\nFunction: %s' % func)
        print('Call addresses:')
        for ea in addrs:
            print('  0x{:X}'.format(ea))

if __name__ == '__main__':
    input_calls = find_calls(INPUT_FUNCTIONS)
    unsafe_calls = find_calls(UNSAFE_FUNCTIONS)

    print_report('INPUT FUNCTION CALLS', input_calls)
    print_report('UNSAFE FUNCTION CALLS', unsafe_calls)
