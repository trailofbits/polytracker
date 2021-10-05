#!/usr/bin/env python3
import sys
import subprocess

args = list(sys.argv[1:])
final = ["llvm-link", "--only-needed"] + args
subprocess.check_call(final)
