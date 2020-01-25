#!/usr/bin/env python3

import struct
from kitty.targets import ClientTarget
from katnip.controllers.client.process import ClientProcessController
from kitty.interfaces import WebInterface
from kitty.fuzzers import ClientFuzzer
from kitty.model import GraphModel, Template
from kitty.model.low_level.aliases import *
from kitty.model.low_level.field import *
from lib104_server_class import *


################# Modified Stack #################

#ASDU struct
class struct_anon_6(Structure):
    pass

struct_anon_6.__slots__ = [
    'parameters',
    'asdu',
    'asduHeaderLength',
    'payload',
    'payloadSize',
]
struct_anon_6._fields_ = [
    ('parameters', CS101_AppLayerParameters),
    ('asdu', POINTER(c_uint8)),
    ('asduHeaderLength', c_int),
    ('payload', POINTER(c_uint8)),
    ('payloadSize', c_int)
]
CS101_ASDU_i = POINTER(struct_anon_6)


class My104Stack(IEC60870_5_104_server):

    def __init__(self):
      self.fuzzer = None
      self.backup_d = []
      self.backup_p = None
      self.backup_s = 0
      self.logger = logging.getLogger('kitty') 
      super(My104Stack, self).__init__()

    def set_fuzzer(self, fuzzer):
      self.fuzzer = fuzzer

    def restore_backup(self):
      if self.backup_p != None and self.backup_d != None and self.backup_s > 0:
        for i in range(self.backup_s):
          self.backup_p[i] = self.backup_d[i]
        self.backup_d = None
        self.backup_p = None
        self.backup_s = 0

    def raw_msg(self, param, connection, p_msg, p_size, sent):
      #some responses are defined on the heap of the library, so when we overwrite them, we overwrite the definition. 
      #We restore it next time this function gets called
      self.restore_backup()

      #the library used has been modified that size is a pointer instead of an int, when data is send
      if sent == True: 
        size = int(p_size.contents.value)
      else: #when data is received, size is actually a value(not a pointer), so a conversion has to be made
        size = int.from_bytes(p_size, byteorder='little', signed=True)

      #size = -1 happens when raw_msg is called during a disconnect
      if size > 0: 
        char_array = (ctypes.c_ubyte * size).from_address(ctypes.addressof(p_msg.contents))
        if sent == True:   
          self.logger.info('>>>>>>>>>>>>>>> SEND >>>>>>>>>>>>>>>>>')             
          if char_array[0] == 0x68 and char_array[1] == 0x04 and char_array[2] == 0x0b: #startdt
            self.logger.info('StartDT server response:')
            self.handle_StartDT(char_array ,size)

          if char_array[0] == 0x68 and char_array[1] == 0x04 and char_array[2] == 0x23: #stopdt
            self.logger.info('StopDT server response:')
            self.handle_StopDT(char_array ,size)

          if char_array[0] == 0x68 and char_array[1] == 0x04 and char_array[2] == 0x83: #testfr
            self.logger.info('Testfr server response:')
            self.handle_Testfr(char_array ,size)

          self.logger.info(bytearray(char_array))
        else:
          self.logger.info('<<<<<<<<<<<<<<<< RECV <<<<<<<<<<<<<<<<')
          self.logger.info(bytearray(char_array))


    def handle_StartDT(self, msg_p, msg_size):
      resp =  self.fuzzer.get_mutation(stage='get_startdt', data={})
      if resp != None:
        #backup original startdt msg, as the static array will get overwritten by the fuzzer
        self.backup_p = msg_p
        self.backup_d = [ctypes.c_ubyte] * msg_size
        for i in range(msg_size):
          self.backup_d[i] = msg_p[i]
        self.backup_s = msg_size  
         #replace msg with fuzzed string
        for i in range(msg_size):
          msg_p[i] = resp[i]
        self.logger.info('! FUZZ startdt !')
        

    def handle_StopDT(self, msg_p, msg_size):
      resp =  self.fuzzer.get_mutation(stage='get_stopdt', data={})
      if resp != None:
        #backup original startdt msg, as the static array will get overwritten by the fuzzer
        self.backup_p = msg_p
        self.backup_d = [ctypes.c_ubyte] * msg_size
        for i in range(msg_size):
          self.backup_d[i] = msg_p[i]
        self.backup_s = msg_size  
         #replace msg with fuzzed string
        for i in range(msg_size):
          msg_p[i] = resp[i]
        self.logger.info('! FUZZ stopdt !')

    def handle_Testfr(self, msg_p, msg_size):
      resp =  self.fuzzer.get_mutation(stage='get_testfr', data={})
      if resp != None:
        #backup original startdt msg, as the static array will get overwritten by the fuzzer
        self.backup_p = msg_p
        self.backup_d = [ctypes.c_ubyte] * msg_size
        for i in range(msg_size):
          self.backup_d[i] = msg_p[i]
        self.backup_s = msg_size  
         #replace msg with fuzzed string
        for i in range(msg_size):
          msg_p[i] = resp[i]
        self.logger.info('! FUZZ testfr !')


    def ASDU_h(self, param, connection, asdu):
      if (CS101_ASDU_getTypeID(asdu) == C_SC_NA_1):
          print("received single command\n")
          if  (CS101_ASDU_getCOT(asdu) == CS101_COT_ACTIVATION):
              io = CS101_ASDU_getElement(asdu, 0)
              if (InformationObject_getObjectAddress(io) == 5000):
                  sc = cast( io, SingleCommand)
                  print(f">>>IOA: {InformationObject_getObjectAddress(io)} switch to {SingleCommand_getState(sc)}")
                  CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON)
                  
                  c_asdu = cast(asdu, CS101_ASDU_i)
                  self.handle_ASDU(c_asdu)
                  
              else:
                  CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA)
              InformationObject_destroy(io)
          else:
              CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_COT)
          IMasterConnection_sendASDU(connection, asdu)
          return True
      return False


    def handle_ASDU(self,c_asdu):
      size = c_asdu.contents.asduHeaderLength + c_asdu.contents.payloadSize
      cc = (ctypes.c_ubyte * size).from_address(ctypes.addressof(c_asdu.contents.asdu.contents))
      resp =  self.fuzzer.get_mutation(stage='get_ASDU', data={})
      if resp != None:
        #replace msg with fuzzed string
        for i in range(size):
          cc[i] = resp[i]
        self.logger.info('! FUZZ ASDU !')


################# Data Model #################

get_startdt = Template(name='get_startdt', fields=[
    UInt8(value=0x68, name='startbyte', fuzzable=False),
    UInt8(value=0x04, name='len', fuzzable=False),
    UInt16(value=0x0b00, name='c1', fuzzable=False),
    UInt16(value=0x0000, name='c2', fuzzable=False)
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

#note, thsi is only the actual ASDU frame, the APCI(which makes together with the ASDU the APDU) is not included
get_ASDU = Template(name='get_ASDU', fields=[
    UInt8(value=0x2d, name='type'),
    UInt8(value=0x01, name='num_of_obj'),
    UInt8(value=0x07, name='COT'),
    UInt8(value=0x00, name='org_addr'),
    UInt16(value=0x0100, name='ASDU_field_addr'),
    UInt8(value=0x88, name='obj addr1'),
    UInt8(value=0x13, name='obj addr2'),
    UInt8(value=0x00, name='obj addr3'),
    UInt8(value=0x01, name='__')
    ])

################# Actual fuzzer code #################

target = ClientTarget(name='104Target')
controller = ClientProcessController(
        "simple_client_single",
        "./simple_client_single",
        ["127.0.0.1"]
    )
target.set_controller(controller)
target.set_mutation_server_timeout(20)
 

model = GraphModel()
model.connect(get_startdt)
model.connect(get_startdt, get_ASDU)
#model.connect(get_startdt, get_stopdt)
#model.connect(get_startdt, get_testfr)
#model.connect(get_testfr, get_stopdt)

fuzzer = ClientFuzzer(name='104 Fuzzer')
fuzzer.set_model(model)
fuzzer.set_target(target)
fuzzer.set_interface(WebInterface(host='0.0.0.0', port=26000))
fuzzer.set_delay_between_tests(0.1)

my_stack = My104Stack()
my_stack.set_fuzzer(fuzzer)
fuzzer.start()
my_stack.start()


