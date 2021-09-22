#!/usr/bin/env python3
import sys
import subprocess

args = [x for x in sys.argv[1:]]
final = ["llvm-link", "--only-needed"] + args
subprocess.check_call(final)