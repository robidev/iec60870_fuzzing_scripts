#!/usr/bin/env python3
#from binascii import hexlify

from kitty.model import GraphModel, Template
from kitty.interfaces import WebInterface
from kitty.fuzzers import ServerFuzzer
from kitty.model.low_level.aliases import *
from kitty.model.low_level.field import *
from katnip.targets.tcp import TcpTarget
from katnip.controllers.server.local_process import LocalProcessController
import os
import sys
import time
from subprocess import Popen, PIPE

#localprocesscontroller overwrite for having subprocess stdout in console
class MyLocalProcessController(LocalProcessController):
  def pre_test(self, test_number):
      '''start the victim'''
      super(LocalProcessController, self).pre_test(test_number)
      if self._start_each_test or not self._is_victim_alive():
          if self._process:
              self._stop_process()
          cmd = [self._process_path] + self._process_args
          self._process = Popen(cmd)#, stdout=PIPE, stderr=PIPE)
          if self._delay_after_start:
              time.sleep(self._delay_after_start)
      self.report.add('process_name', self._process_name)
      self.report.add('process_path', self._process_path)
      self.report.add('process_args', self._process_args)
      self.report.add('process_id', self._process.pid)

#tcptarget overwrite for perfoming additional post-checks (not yet implemented)
class MyTcpTarget(TcpTarget):
  def post_test(self, test_num):
     super(MyTcpTarget, self).post_test(test_num)
      

get_startdt = Template(name='get_startdt', fields=[
    UInt8(value=0x68, name='startbyte', fuzzable=False),
    UInt8(value=0x04, name='len'),
    UInt16(value=0x0700, name='c1'),
    UInt16(value=0x0000, name='c2')
    ])

get_stopdt = Template(name='get_stopdt', fields=[
    UInt8(value=0x68, name='startbyte'),
    UInt8(value=0x04, name='len'),
    UInt16(value=0x1300, name='c1'),
    UInt16(value=0x0000, name='c2')
    ])

get_testfr = Template(name='get_testfr', fields=[
    UInt8(value=0x68, name='startbyte'),
    UInt8(value=0x04, name='len'),
    UInt16(value=0x4300, name='c1'),
    UInt16(value=0x0000, name='c2')
    ])

get_GI = Template(name='get_GI', fields=[
    UInt8(value=0x68, name='startbyte'),
    UInt8(value=0x0e, name='len'),
    UInt16(value=0x0000, name='c1'),
    UInt16(value=0x0200, name='c2'),

    UInt8(value=0x64, name='type'),
    UInt8(value=0x01, name='num_of_obj'),
    UInt8(value=0x06, name='COT'),
    UInt8(value=0x00, name='org_addr'),
    UInt16(value=0x0100, name='ASDU_field_addr'),
    UInt8(value=0x00, name='obj addr1'),
    UInt8(value=0x00, name='obj addr2'),
    UInt8(value=0x00, name='obj addr3'),
    UInt8(value=0x14, name='GI')
    ])


target_ip = '127.0.0.1'
target_port = 2404
web_port = 26001

# Define session target
target = MyTcpTarget(
  name='session_test_target', 
  host=target_ip, 
  port=target_port, 
  timeout=5, 
  max_retries=10, 
  logger=None)

# Make target expect response
target.set_expect_response(True)

# Define controller
controller = MyLocalProcessController(
  name='simple_server', 
  process_path='./simple_server_orig', 
  process_args=[], 
  delay_after_start=0.2, 
  start_each_test=False, 
  logger=None)


target.set_controller(controller)

# Define model
model = GraphModel()

model.connect(get_startdt)
model.connect(get_startdt, get_stopdt)

model.connect(get_startdt, get_testfr)
model.connect(get_testfr, get_stopdt)

model.connect(get_startdt, get_GI)
model.connect(get_GI, get_stopdt)


# Define fuzzer
fuzzer = ServerFuzzer(option_line="")
fuzzer.set_interface(WebInterface(port=web_port))
fuzzer.set_model(model)
fuzzer.set_target(target)
fuzzer.set_delay_between_tests(0.2)
fuzzer.start()