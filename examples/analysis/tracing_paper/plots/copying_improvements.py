from matplotlib import pyplot
from typing import List

class Command:
  def __init__(self, name: str, user_time: float, sys_time: float):
    self.name = name
    self.user_time = user_time
    self.sys_time = sys_time

class Tdag:
  def __init__(self, num_labels: int, num_cflog_entries: int, tdag_name: str, file_name: str, origin: str, command: Command):
    self.num_labels = num_labels
    self.num_cflog_entries = num_cflog_entries
    self.tdag_name = tdag_name
    self.file_name = file_name
    self.origin = origin
    self.command = command

# from kaoudis/eval branch commit 787c0309 (before memoryview changes)
tdags_at_787c0309_cflog_info: List[Tdag] = [
  Tdag(
    num_labels=1086,
    num_cflog_entries=279,
    tdag_name='Debug.tdag',
    file_name=,
    origin='nitro',
    command=Command(
      name='polytracker info --cflog',
      user_time=1.87,
      sys_time=0.15)),
  Tdag(
    num_labels=1401,
    num_cflog_entries=321,
    tdag_name='Release.tdag',
    file_name='hackathonFive-nitf/jitc/nitf2.0/U_2001E.NTF',
    origin='nitro',
    command=Command(
      name='polytracker info --cflog',
      user_time=0.95,
      sys_time=0.09)),
  Tdag(
    num_labels=1201415662,
    num_cflog_entries=,
    tdag_name='re3eot.tdag',
    file_name='re3eot.png',
    origin='libpng',
    command=Command(
      name='polytracker info --cflog',
      user_time=,
      sys_time=)),
  Tdag(
    num_labels=,
    num_cflog_entries=,
    tdag_name='manual.tdag',
    file_name='manual.png',
    origin='libpng',
    command=Command(
      name='polytracker info --cflog',
      user_time=,
      sys_time=,)),
  Tdag(
    num_labels=263496,
    num_cflog_entries=10459,
    tdag_name='dcmtk_debug.tdag',
    file_name='release_2002/imgdisplay_testcases/dish_p01.dcm',
    origin='dcmtk',
    command=Command(
      name='polytracker info --cflog',
      user_time=42.36,
      sys_time=0.30,)),
  Tdag(
    num_labels=263865,
    num_cflog_entries=8887,
    tdag_name='dcmtk_release.tdag',
    file_name='release_2002/imgdisplay_testcases/dish_p01.dcm',
    origin='dcmtk', command=Command(
      name='polytracker info --cflog',
      user_time=6.04,
      sys_time=0.12,),
  Tdag(
    num_labels=,
    num_cflog_entries=,
    name='',
    origin='libjpeg-9e',
    command=Command(
      name='polytracker info --cflog',
      user_time=,
      sys_time=,)),
  Tdag(
    num_labels=,
    num_cflog_entries=,
    name='',
    origin='libjpeg-9e',
    command=Command(
      name='polytracker info --cflog',
      user_time=,
      sys_time=,)),
  Tdag(
    num_labels=,
    num_cflog_entries=,
    name='',
    origin='libjpeg-turbo',
    command=Command(
      name='polytracker info --cflog',
      user_time=,
      sys_time=,)),
  Tdag(
    num_labels=,
    num_cflog_entries=,
    name='',
    origin='libjpeg-turbo',
    command=Command(
      name='polytracker info --cflog',
      user_time=,
      sys_time=,)),
  Tdag(
    num_labels=,
    num_cflog_entries=,
    name='',
    origin='openjpeg',
    command=Command(
      name='polytracker info --cflog',
      user_time=,
      sys_time=,)),
  Tdag(
    num_labels=,
    num_cflog_entries=,
    name='',
    origin='openjpeg',
    command=Command(
      name='polytracker info --cflog',
      user_time=,
      sys_time=,)),
]

def plot(tdags: List[Tdag]):
  for tdag in tdags:
    pyplot.plot(tdag.num_labels, tdag.num_cflog_entries)
  pyplot.legend([f"{tdag.name}, {tdag.origin}" for tdag in tdags_at_787c0309_cflog_info])
  pyplot.xlabel('Labels')
  pyplot.ylabel('CFLog entries')
  pyplot.show()

  for tdag in tdags:
    pyplot.plot(tdag.command.user_time, tdag.num_cflog_entries)
  pyplot.legend([f"{tdag.name}, {tdag.origin}" for tdag in tdags_at_787c0309_cflog_info])
  pyplot.xlabel('`time` userspace time (seconds)')
  pyplot.ylabel('CFLog entries')
  pyplot.show()

