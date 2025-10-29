import os
import re
import sys
import logging
import shutil
import hashlib
import random
import subprocess
import argparse
from datetime import datetime

logger = logging.getLogger("AdvancedFuzzer")


def setup_logger(debug=False):
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    log_file = f"fuzzer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return log_file


class Fuzzer:
    def __init__(self, config_path, debug=False, windbg_path=None, target_program=None):
        self.config_path = config_path
        self.backup_path = f"{config_path}.bak"
        self.original_hash = None
        self.debug = debug
        # self.windbg_path = windbg_path or r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"
        self.windbg_path = windbg_path or r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe"
        self.target_program = target_program or "vuln1.exe"  # По умолчанию vuln1.exe
        self.setup_environment()
        self.crash_count = 0
        self.last_trace_hash = None
        self.boundary_values = [
            0x00, 0xFF,
            0xFFFF, 0xFFFF // 2, 0xFFFF // 2 + 1, 0xFFFF // 2 - 1,
            0xFFFFFF, 0xFFFFFFFF
        ]

    def setup_environment(self):
        if not os.path.exists(self.config_path):
            logger.error("Config file not found!")
            sys.exit(1)
        shutil.copyfile(self.config_path, self.backup_path)
        self.original_hash = self.calculate_hash(self.config_path)
        logger.info(f"Backup created: {self.backup_path}")

    def calculate_hash(self, file_path):
        with open(file_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()

    def restore_config(self):
        shutil.copyfile(self.backup_path, self.config_path)
        logger.debug("Config restored from backup")

    def parse_drcov_trace(self, coverage_data):
        trace = []
        lines = coverage_data.decode('utf-8', errors='replace').split('\n')
        for line in lines:
            if 'module[' in line:
                parts = line.split(':')
                if len(parts) < 2:
                    continue
                module_part = parts[0].strip()
                address_part = parts[1].split(',')[0].strip()

                if not any(module_part.endswith(f'module[{i}]') for i in [0, 1]):
                    continue

                try:
                    address = int(address_part, 16)
                    trace.append(address)
                except ValueError:
                    continue
        return trace

    def get_trace_hash(self, process_result):
        if not process_result:
            return None
        trace = self.parse_drcov_trace(process_result.stderr)
        return hashlib.md5(str(trace).encode()).hexdigest()

    def mutate_bytes_feedback(self, data, position):
        original_data = bytearray(data)
        mutated = False

        num_bytes = random.choice([1, 2])
        max_offset = len(data) - position - num_bytes

        if max_offset <= 0:
            return data, False

        offset = random.randint(0, max_offset)
        mutation_value = random.choice(self.boundary_values)

        try:
            for i in range(num_bytes):
                byte_offset = position + offset + i
                if byte_offset >= len(original_data):
                    break
                original_data[byte_offset] = (mutation_value >> (8 * i)) & 0xFF
            mutated = True
        except Exception as e:
            logger.error(f"Mutation error: {str(e)}")

        return bytes(original_data), mutated

    def run_target(self):
        try:
            if "7z.exe" in self.target_program or "Rar.exe" in self.target_program:
                drrun_path = r".\DynamoRIO-Windows-11.90.20196\bin64\drrun.exe"
            else:
                drrun_path = r".\DynamoRIO-Windows-11.90.20196\bin32\drrun.exe"

            dr_process = subprocess.run(
                [drrun_path,
                 "-t", "drcov", "-dump_text", "-logdir", "coverage", "--", self.target_program, self.config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10
            )
            crash_detected = self.analyze_execution(dr_process)
            self.log_coverage(dr_process.stderr)
            return crash_detected, dr_process
        except subprocess.TimeoutExpired:
            logger.warning("Process timeout!")
            return True, None
        except Exception as e:
            logger.error(f"Execution error: {str(e)}")
            return False, None

    def analyze_execution(self, process_result):
        if process_result is None:
            return False
        crash_signals = ['SEGV', 'ILL', 'ABRT', 'FPE', 'BUS']
        stdout = process_result.stdout.decode('utf-8', errors='replace')
        stderr = process_result.stderr.decode('utf-8', errors='replace')
        if process_result.returncode not in [0, 1]:
            logger.debug(f"Non-zero exit code: {process_result.returncode}")
            return True
        if any(sig in stderr for sig in crash_signals):
            logger.debug("Crash signal detected")
            return True
        error_patterns = [
            'segmentation-fault', 'access-violation',
            'buffer-overflow', 'stack-smashing'
        ]
        if any(patt in stdout.lower() or patt in stderr.lower() for patt in error_patterns):
            logger.debug("Error pattern detected")
            return True
        return False

    def log_coverage(self, coverage_data):
        if b"Coverage data" in coverage_data:
            logger.info("New code coverage data recorded")

    def save_crash(self, iteration, data, process_result):
        self.crash_count += 1
        crash_dir = f"crashes/crash_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(crash_dir, exist_ok=True)

        crash_config = os.path.join(crash_dir, "crash_config.bin")
        with open(crash_config, 'wb') as f:
            f.write(data)

        if process_result:
            with open(os.path.join(crash_dir, "execution.log"), 'w') as f:
                f.write("=== STDOUT ===\n")
                f.write(process_result.stdout.decode('utf-8', errors='replace'))
                f.write("\n=== STDERR ===\n")
                f.write(process_result.stderr.decode('utf-8', errors='replace'))

        if self.windbg_path:
            if not os.path.isfile(self.windbg_path):
                logger.error(f"Windbg executable not found at {self.windbg_path}")
                return

            temp_backup = f"{self.config_path}.temp.bak"
            try:
                shutil.copyfile(self.config_path, temp_backup)

                with open(self.config_path, 'wb') as f:
                    f.write(data)

                dump_file = os.path.join(crash_dir, "crash.dmp")
                log_file = os.path.join(crash_dir, "windbg.log")

                windbg_cmd = [
                    self.windbg_path,
                    '-c',
                    f'.dump /ma {dump_file};'
                    f'.logopen {log_file};'
                    'g;'  
                    '!analyze -v;'
                    '.logclose;'
                    'q',
                    'vuln/vuln1.exe'
                ]

                try:
                    subprocess.run(
                        windbg_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=20
                    )
                    logger.info(f"Windbg analysis completed for crash {crash_dir}")
                except subprocess.TimeoutExpired:
                    logger.warning("Windbg execution timed out")
                except Exception as e:
                    logger.error(f"Windbg execution failed: {str(e)}")

            finally:
                if os.path.exists(temp_backup):
                    shutil.copyfile(temp_backup, self.config_path)
                    os.remove(temp_backup)
                    logger.debug("Original config restored after Windbg analysis")

        logger.warning(f"Crash saved in: {crash_dir}")

    def mutate_append(self, data, step):
        cleaned = data.rstrip(b'\x00')
        return cleaned + b'A' * step

    def mutate_bytes(self, data, position):
        mutation = random.choice([
            lambda d: d[:position] + bytes([0x00] * len(d[:position])) + d[position:],
            lambda d: d[:position] + bytes([0xFF] * len(d[:position])) + d[position:],
            lambda d: d[:position] + os.urandom(len(d[:position])) + d[position:]
        ])
        return mutation(data)

    def replace_specific_byte(self, data, byte_position, new_byte_value):
        if byte_position < 0 or byte_position >= len(data):
            logger.error(f"Invalid byte position: {byte_position}. File size: {len(data)} bytes")
            return data, False

        if new_byte_value < 0 or new_byte_value > 255:
            logger.error(f"Invalid byte value: {new_byte_value}. Must be 0-255")
            return data, False

        modified_data = bytearray(data)
        old_value = modified_data[byte_position]
        modified_data[byte_position] = new_byte_value

        logger.info(f"Replaced byte at position {byte_position}: 0x{old_value:02X} -> 0x{new_byte_value:02X}")
        return bytes(modified_data), True

    def run_mode(self, mode, iterations=10000):
        logger.info(f"Starting fuzzing in mode {mode}")

        if mode == 3:
            try:
                with open(self.config_path, 'rb') as f:
                    file_data = f.read()
                file_size = len(file_data)

                print(f"\nФайл {self.config_path} содержит {file_size} байт")
                print("Позиции байтов: от 0 до", file_size - 1)

                while True:
                    try:
                        byte_position = int(input("Введите номер байта для замены (0-{}): ".format(file_size - 1)))
                        if 0 <= byte_position < file_size:
                            break
                        else:
                            print(f"Ошибка: позиция должна быть от 0 до {file_size - 1}")
                    except ValueError:
                        print("Ошибка: введите корректное число")

                while True:
                    try:
                        new_byte_value = int(input("Введите новое значение байта (0-255): "))
                        if 0 <= new_byte_value <= 255:
                            break
                        else:
                            print("Ошибка: значение должно быть от 0 до 255")
                    except ValueError:
                        print("Ошибка: введите корректное число")

                logger.info(f"Mode 3: Replacing byte at position {byte_position} with value {new_byte_value}")

            except Exception as e:
                logger.error(f"Error getting user input for mode 3: {str(e)}")
                return

        try:
            for i in range(1, iterations + 1):
                self.restore_config()
                with open(self.config_path, 'rb') as f:
                    original_data = f.read()
                if mode == 1:
                    modified_data = self.mutate_append(original_data, i)

                    with open(self.config_path, 'wb') as f:
                        f.write(modified_data)

                    crash_detected, result = self.run_target()
                    current_trace_hash = self.get_trace_hash(result)

                    if current_trace_hash != self.last_trace_hash:
                        logger.info(f"Iteration {i} - NEW CODE PATH DETECTED")
                        self.last_trace_hash = current_trace_hash

                    if crash_detected:
                        logger.info(f"Iteration {i} - CRASH DETECTED")
                        self.save_crash(i, modified_data, result)

                elif mode == 2:
                    pos = original_data.find(b'/start')
                    if pos == -1:
                        logger.error("'/start' marker not found!")
                        return

                    modified_data, mutated = self.mutate_bytes_feedback(original_data, pos)
                    if not mutated:
                        continue

                    with open(self.config_path, 'wb') as f:
                        f.write(modified_data)

                    crash_detected, result = self.run_target()
                    current_trace_hash = self.get_trace_hash(result)

                    if current_trace_hash != self.last_trace_hash:
                        logger.info(f"Iteration {i} - NEW CODE PATH DETECTED")
                        self.last_trace_hash = current_trace_hash
                    else:
                        self.restore_config()

                    if crash_detected:
                        logger.info(f"Iteration {i} - CRASH DETECTED")
                        self.save_crash(i, modified_data, result)

                elif mode == 3:
                    modified_data, success = self.replace_specific_byte(original_data, byte_position, new_byte_value)
                    if not success:
                        logger.error("Failed to replace byte")
                        continue

                    new_config_path = f"{self.config_path}.modified"
                    with open(new_config_path, 'wb') as f:
                        f.write(modified_data)

                    original_config_path = self.config_path
                    self.config_path = new_config_path

                    crash_detected, result = self.run_target()
                    current_trace_hash = self.get_trace_hash(result)

                    self.config_path = original_config_path

                    if current_trace_hash != self.last_trace_hash:
                        logger.info(f"Iteration {i} - NEW CODE PATH DETECTED")
                        self.last_trace_hash = current_trace_hash

                    if crash_detected:
                        logger.info(f"Iteration {i} - CRASH DETECTED")
                        self.save_crash(i, modified_data, result)

                    logger.info("Mode 3: Single byte replacement completed")
                    logger.info(f"Original config preserved: {original_config_path}")
                    logger.info(f"Modified config saved to: {new_config_path}")
                    break

                if i % 50 == 0:
                    logger.info(f"Iteration {i}/{iterations} - Crashes: {self.crash_count}")
                    if mode == 2:
                        logger.debug(f"Current trace hash: {self.last_trace_hash}")
                if self.crash_count > 0:
                    break
        finally:
            if mode != 3:
                self.restore_config()
                logger.info("Fuzzing completed. Original config restored.")
            else:
                logger.info("Mode 3 completed. Original config was never modified.")


def main():
    parser = argparse.ArgumentParser(description="Fuzzer")
    parser.add_argument("config", help="Path to config file")
    parser.add_argument("-m", "--mode", type=int, choices=[1, 2, 3], required=True,
                        help="Fuzzing mode: 1 - Append, 2 - Byte mutation, 3 - Specific byte replacement")
    parser.add_argument("-i", "--iterations", type=int, default=10000,
                        help="Number of iterations")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Enable debug mode")
    parser.add_argument("--windbg-path", type=str, default=None,
                        help="Path to Windbg executable") # (optional, for crash analysis)")
    parser.add_argument("--target", type=str, default="vuln1.exe",
                        help="Target program to fuzz (e.g., 7z.exe, Rar.exe)")

    args = parser.parse_args()
    log_file = setup_logger(args.debug)
    logger.info(f"Starting fuzzer with config: {args.config}")

    try:
        fuzzer = Fuzzer(args.config, args.debug, args.windbg_path, args.target)
        fuzzer.run_mode(args.mode, args.iterations)
    except KeyboardInterrupt:
        logger.info("Fuzzing interrupted by user")
    except Exception as e:
        logger.critical(f"Critical error: {str(e)}")
    finally:
        logger.info(f"Logs saved to: {log_file}")


if __name__ == "__main__":
    os.makedirs("crashes", exist_ok=True)
    os.makedirs("coverage", exist_ok=True)
    main()