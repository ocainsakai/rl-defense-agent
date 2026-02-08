#!/usr/bin/env python3
"""
CLI Runner cho Test Suite - RL Defense Agent

Giao dien terminal de chay va quan ly tests.
"""

import subprocess
import sys
import os

# ANSI colors
class C:
    BOLD = '\033[1m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    DIM = '\033[2m'
    RESET = '\033[0m'

BANNER = f"""
{C.CYAN}{C.BOLD}{'='*60}
   RL DEFENSE AGENT - TEST RUNNER
{'='*60}{C.RESET}
"""

MENU = f"""
{C.BOLD}  Chon nhom test:{C.RESET}

  {C.GREEN}[1]{C.RESET}  Chay TAT CA tests
  {C.GREEN}[2]{C.RESET}  Unit tests          {C.DIM}(nhanh, khong can dataset){C.RESET}
  {C.GREEN}[3]{C.RESET}  Integration tests   {C.DIM}(full pipeline){C.RESET}
  {C.GREEN}[4]{C.RESET}  SQLi tests          {C.DIM}(payload detection){C.RESET}
  {C.GREEN}[5]{C.RESET}  Kruegel tests       {C.DIM}(web anomaly models){C.RESET}
  {C.GREEN}[6]{C.RESET}  Dataset tests       {C.DIM}(can sqli.csv / csic_database.csv){C.RESET}
  {C.GREEN}[7]{C.RESET}  Tat ca NGOAI TRU dataset {C.DIM}(nhanh nhat){C.RESET}

  {C.YELLOW}[8]{C.RESET}  Chay 1 file test cu the
  {C.YELLOW}[9]{C.RESET}  Tim test theo ten   {C.DIM}(-k keyword){C.RESET}

  {C.MAGENTA}[0]{C.RESET}  Thoat
"""

PYTEST_CMD = [sys.executable, '-m', 'pytest', 'test/']

PRESETS = {
    '1': ([], 'TAT CA tests'),
    '2': (['-m', 'unit'], 'Unit tests'),
    '3': (['-m', 'integration'], 'Integration tests'),
    '4': (['-m', 'sqli'], 'SQLi tests'),
    '5': (['-m', 'kruegel'], 'Kruegel tests'),
    '6': (['-m', 'dataset'], 'Dataset tests'),
    '7': (['-m', 'not dataset'], 'Tat ca ngoai tru dataset'),
}

TEST_FILES = {
    '1': 'test/test_packet_parser.py',
    '2': 'test/test_flow_state.py',
    '3': 'test/test_flow_manager.py',
    '4': 'test/test_features.py',
    '5': 'test/test_full_pipeline.py',
    '6': 'test/test_behavioral_features.py',
    '7': 'test/test_sqli_simple.py',
    '8': 'test/test_sqli_detection.py',
    '9': 'test/test_sqli_analysis.py',
    '10': 'test/test_sqli_full_pipeline.py',
    '11': 'test/test_csic_dataset.py',
    '12': 'test/test_csic_full_pipeline.py',
    '13': 'test/test_kruegel_features.py',
}


def run_pytest(extra_args, desc):
    """Chay pytest voi args va in header."""
    print(f"\n{C.CYAN}{C.BOLD}>> {desc}{C.RESET}")
    print(f"{C.DIM}   pytest {' '.join(extra_args)}{C.RESET}\n")

    cmd = PYTEST_CMD + ['-v', '--tb=short'] + extra_args
    result = subprocess.run(cmd)
    return result.returncode


def choose_file():
    """Menu chon file test."""
    print(f"\n{C.BOLD}  Chon file test:{C.RESET}\n")
    for num, path in sorted(TEST_FILES.items(), key=lambda x: int(x[0])):
        name = os.path.basename(path).replace('.py', '').replace('test_', '')
        print(f"  {C.GREEN}[{num:>2}]{C.RESET}  {name:30s} {C.DIM}{path}{C.RESET}")

    print()
    choice = input(f"  {C.BOLD}Nhap so (Enter de quay lai): {C.RESET}").strip()

    if choice in TEST_FILES:
        path = TEST_FILES[choice]
        run_pytest([path], f"File: {path}")
    elif choice:
        print(f"  {C.RED}Khong hop le!{C.RESET}")


def search_test():
    """Tim test theo keyword."""
    keyword = input(f"\n  {C.BOLD}Nhap keyword (-k): {C.RESET}").strip()
    if keyword:
        run_pytest(['-k', keyword], f"Tim: '{keyword}'")


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    while True:
        print(BANNER)
        print(MENU)

        choice = input(f"  {C.BOLD}Chon [0-9]: {C.RESET}").strip()

        if choice == '0':
            print(f"\n  {C.CYAN}Bye!{C.RESET}\n")
            break
        elif choice in PRESETS:
            args, desc = PRESETS[choice]
            run_pytest(args, desc)
        elif choice == '8':
            choose_file()
        elif choice == '9':
            search_test()
        else:
            print(f"  {C.RED}Khong hop le! Chon 0-9.{C.RESET}")

        input(f"\n  {C.DIM}Enter de tiep tuc...{C.RESET}")


if __name__ == '__main__':
    main()
