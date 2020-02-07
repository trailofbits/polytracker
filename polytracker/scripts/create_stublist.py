#!/usr/bin/env python
#===- lib/dfsan/scripts/build-libc-list.py ---------------------------------===#
#
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
# The purpose of this script is to identify every function symbol in a set of
# libraries (in this case, libc and libgcc) so that they can be marked as
# uninstrumented, thus allowing the instrumentation pass to treat calls to those
# functions correctly.

import os
import subprocess
import sys
from optparse import OptionParser
import glob 

def defined_function_list(object):
  functions = []
  readelf_proc = subprocess.Popen(['readelf', '-s', '-W', object],
                                  stdout=subprocess.PIPE)
  readelf = readelf_proc.communicate()[0].decode(errors='replace').split('\n')
  if readelf_proc.returncode != 0:
    raise subprocess.CalledProcessError(readelf_proc.returncode, 'readelf')
  for line in readelf:
    if (line[31:35] == 'FUNC' or line[31:36] == 'IFUNC') and \
       line[39:44] != 'LOCAL' and \
       line[55:58] != 'UND':
      function_name = line[59:].split('@')[0]
      functions.append(function_name)
  return functions

libs = [sys.argv[1]]

functions = []
for l in libs:
  if os.path.exists(l):
    functions += defined_function_list(l)
  else:
    print >> sys.stderr, 'warning: library %s not found' % l

functions = list(set(functions))
functions.sort()

for f in functions:
  f = f.replace("dfsw$", "")
  f = f.replace("dfs$", "")
  print('fun:%s=uninstrumented' % f)
  print('fun:%s=discard' % f)
