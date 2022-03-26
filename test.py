#!/usr/bin/env python3
import argparse, sys, os, subprocess, platform

DEPLOY_PATH = "deploy"


class Test:
  def __init__(self):
    self.testNum = 1
  def testPass(self, label):
    print("Test \033[1m{0}\033[0m \033[38;5;208m{1}\033[0m \033[1m\033[32mOK\033[0m".format(self.testNum, label))
    self.testNum = self.testNum + 1
        
  def testFail(self, label):
    print("Test \033[1m{0}\033[0m \033[38;5;208m{1}\033[0m \033[1m\033[31mFAILED\033[0m".format(self.testNum, label))
    sys.exit(1)
        
  def testNotSupported(self, label):
    print("Test \033[1m{0}\033[0m \033[38;5;208m{1}\033[0m \033[1m\033[33mNOT SUPPORTED\033[0m".format(self.testNum, label))
    self.testNum = self.testNum + 1

  def getNum(self):
    return self.testNum
    
def execProcess(args):
  process = subprocess.Popen(args, shell=False,
    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  stdout, stderr = process.communicate()
  exitCode = process.wait()
  return exitCode

def main(argv):
  machine = platform.machine()
  directory = os.path.join(DEPLOY_PATH, machine)
  elfs = [
    "aes.elf",
    "base64.elf",
    "md2.elf",
    "md4.elf",
    "md5.elf",
    "sha1.elf"
  ]

  t = Test()
  
  for elf in elfs:
    print("Start test \033[1m{0}\033[0m: \033[1m\033[36m{1}\033[0m".format(t.getNum(), elf))
    retCode = execProcess([os.path.join(directory, elf)])
    if retCode == 0:
      t.testPass("{0} exec\t".format(elf))
    elif retCode == 2:
      t.testNotSupported("{0} exec\t".format(elf))
    else:
      t.testFail("{0} exec\t".format(elf))
  print("TEST \033[1m\033[32mPASSED\033[0m")
  
if __name__ == '__main__':
  main(sys.argv[1:])
