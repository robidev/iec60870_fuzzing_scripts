#!/usr/bin/env python3
from lib60870 import *
import time

class IEC60870_5_104_server:

  def printCP56Time2a(self, time):
      print("%02i:%02i:%02i %02i/%02i/%04i" % ( CP56Time2a_getHour(time),
                               CP56Time2a_getMinute(time),
                               CP56Time2a_getSecond(time),
                               CP56Time2a_getDayOfMonth(time),
                               CP56Time2a_getMonth(time),
                               CP56Time2a_getYear(time) + 2000) )

  def clock(self, param, con, asdu, newTime):
    print("Process time sync command with time ")
    self.printCP56Time2a(newTime)
    newSystemTimeInMs = CP56Time2a_toMsTimestamp(newTime)
    #/* Set time for ACT_CON message */
    CP56Time2a_setFromMsTimestamp(newTime, Hal_getTimeInMs())
    #/* update system time here */
    return True

  def GI_h(self, param, connection, asdu, qoi):
      print(f"Received interrogation for group {qoi}")
      if (qoi == 20): #{ /* only handle station interrogation */
          alParams = IMasterConnection_getApplicationLayerParameters(connection)
          IMasterConnection_sendACT_CON(connection, asdu, False)

          #* The CS101 specification only allows information objects without timestamp in GI responses */
          newAsdu = CS101_ASDU_create(alParams, False, CS101_COT_INTERROGATED_BY_STATION, 0, 1, False, False)

          io = cast( MeasuredValueScaled_create(None, 100, -1, IEC60870_QUALITY_GOOD), InformationObject) 

          CS101_ASDU_addInformationObject(newAsdu, io)

          CS101_ASDU_addInformationObject(newAsdu, 
              cast( MeasuredValueScaled_create(cast(io,MeasuredValueScaled),101,23,IEC60870_QUALITY_GOOD), InformationObject)
              )

          CS101_ASDU_addInformationObject(newAsdu, 
              cast( MeasuredValueScaled_create(cast(io,MeasuredValueScaled),102,2300, IEC60870_QUALITY_GOOD), InformationObject)
              )
          
          InformationObject_destroy(io)

          IMasterConnection_sendASDU(connection, newAsdu)

          CS101_ASDU_destroy(newAsdu)
          
          newAsdu = CS101_ASDU_create(alParams, False, CS101_COT_INTERROGATED_BY_STATION,
                      0, 1, False, False)

          io = cast( SinglePointInformation_create(None, 104, True, IEC60870_QUALITY_GOOD), InformationObject)

          CS101_ASDU_addInformationObject(newAsdu, io)

          CS101_ASDU_addInformationObject(newAsdu, 
              cast( SinglePointInformation_create(cast(io,SinglePointInformation), 105, False, IEC60870_QUALITY_GOOD),InformationObject)
              )

          InformationObject_destroy(io)

          IMasterConnection_sendASDU(connection, newAsdu)

          CS101_ASDU_destroy(newAsdu)
          
          newAsdu = CS101_ASDU_create(alParams, True, CS101_COT_INTERROGATED_BY_STATION, 0, 1, False, False)

          io = cast( SinglePointInformation_create(None, 300, True, IEC60870_QUALITY_GOOD), InformationObject)

          CS101_ASDU_addInformationObject(newAsdu, io)
          CS101_ASDU_addInformationObject(newAsdu, cast( SinglePointInformation_create(cast( io, SinglePointInformation), 301, False, IEC60870_QUALITY_GOOD), InformationObject))
          CS101_ASDU_addInformationObject(newAsdu, cast( SinglePointInformation_create(cast( io, SinglePointInformation), 302, True, IEC60870_QUALITY_GOOD), InformationObject))
          CS101_ASDU_addInformationObject(newAsdu, cast( SinglePointInformation_create(cast( io, SinglePointInformation), 303, False, IEC60870_QUALITY_GOOD), InformationObject))
          CS101_ASDU_addInformationObject(newAsdu, cast( SinglePointInformation_create(cast( io, SinglePointInformation), 304, True, IEC60870_QUALITY_GOOD), InformationObject))
          CS101_ASDU_addInformationObject(newAsdu, cast( SinglePointInformation_create(cast( io, SinglePointInformation), 305, False, IEC60870_QUALITY_GOOD), InformationObject))
          CS101_ASDU_addInformationObject(newAsdu, cast( SinglePointInformation_create(cast( io, SinglePointInformation), 306, True, IEC60870_QUALITY_GOOD), InformationObject))
          CS101_ASDU_addInformationObject(newAsdu, cast( SinglePointInformation_create(cast( io, SinglePointInformation), 307, False, IEC60870_QUALITY_GOOD), InformationObject))

          InformationObject_destroy(io)

          IMasterConnection_sendASDU(connection, newAsdu)

          CS101_ASDU_destroy(newAsdu)

          IMasterConnection_sendACT_TERM(connection, asdu)
      else:
          IMasterConnection_sendACT_CON(connection, asdu, True)



  def ASDU_h(self, param, connection, asdu):
      if (CS101_ASDU_getTypeID(asdu) == C_SC_NA_1):
          print("received single command\n")

          if  (CS101_ASDU_getCOT(asdu) == CS101_COT_ACTIVATION):
              io = CS101_ASDU_getElement(asdu, 0)

              if (InformationObject_getObjectAddress(io) == 5000):
                  sc = cast( io, SingleCommand)

                  print(f"IOA: {InformationObject_getObjectAddress(io)} switch to {SingleCommand_getState(sc)}")

                  CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON)

              else:
                  CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA)

              InformationObject_destroy(io)

          else:
              CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_COT)

          IMasterConnection_sendASDU(connection, asdu)

          return True

      return False



  def Conn_req(self, param, address):
    print("New connection request")
    return True

  def Conn_event(self, param, con, event):
    if (event == CS104_CON_EVENT_CONNECTION_OPENED):
        print(f"Connection opened {con}")
    elif (event == CS104_CON_EVENT_CONNECTION_CLOSED):
        print(f"Connection closed {con}")
    elif (event == CS104_CON_EVENT_ACTIVATED):
        print(f"Connection activated {con}")
    elif (event == CS104_CON_EVENT_DEACTIVATED):
        print(f"Connection deactivated {con}")


  def raw_msg(self, param, connection, p_msg, p_size, sent):
    if sent == True:
      #the library used has been modified that size is a pointer instead of an int, when data is send
      size = int(p_size.contents.value)
      print(f"SEND:{size}")
    else:
      #when data is received, size is actually a value(not a pointer), so a conversion has to be made
      size = int.from_bytes(p_size, byteorder='little', signed=True)
      print(f"RECV:{size},")
    if size > 0:
      char_array = (ctypes.c_ubyte * size).from_address(ctypes.addressof(p_msg.contents))
      tt = bytearray(char_array)
      print(' '.join(format(x, '02x') for x in tt))
      if sent == True and char_array[1] == 0x10:
        char_array[6]=0x42

  def __init__(self, ip = "0.0.0.0"):
    self.clockSyncHandler = CS101_ClockSynchronizationHandler(self.clock)
    self.interrogationHandler = CS101_InterrogationHandler(self.GI_h)
    self.asduHandler = CS101_ASDUHandler(self.ASDU_h)
    self.connectionRequestHandler = CS104_ConnectionRequestHandler(self.Conn_req)
    self.connectionEventHandler = CS104_ConnectionEventHandler(self.Conn_event)
    self.rawMessageHandler = CS104_SlaveRawMessageHandler(self.raw_msg)

    self.slave = CS104_Slave_create(100, 100)
    CS104_Slave_setLocalAddress(self.slave, ip)
    #   /* Set mode to a single redundancy group
    CS104_Slave_setServerMode(self.slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP)

    #/* get the connection parameters - we need them to create correct ASDUs */
    self.alParams = CS104_Slave_getAppLayerParameters(self.slave)

    #/* set the callback handler for the clock synchronization command */
    CS104_Slave_setClockSyncHandler(self.slave, self.clockSyncHandler, None)

    #/* set the callback handler for the interrogation command */
    CS104_Slave_setInterrogationHandler(self.slave, self.interrogationHandler, None)

    #/* set handler for other message types */
    CS104_Slave_setASDUHandler(self.slave, self.asduHandler, None)

    #/* set handler to handle connection requests (optional) */
    CS104_Slave_setConnectionRequestHandler(self.slave, self.connectionRequestHandler, None)

    #/* set handler to track connection events (optional) */
    CS104_Slave_setConnectionEventHandler(self.slave, self.connectionEventHandler, None)

    #/* uncomment to log messages */
    CS104_Slave_setRawMessageHandler(self.slave, self.rawMessageHandler, None)

  def start(self):
    CS104_Slave_start(self.slave)

    if CS104_Slave_isRunning(self.slave) == False:
      print("Starting server failed!\n")
      exit(0)

    scaledValue = 0

    while True:
      time.sleep( 1 )
      newAsdu = CS101_ASDU_create(self.alParams, False, CS101_COT_PERIODIC, 0, 1, False, False)
      io = cast(MeasuredValueScaled_create(None, 110, scaledValue, IEC60870_QUALITY_GOOD),InformationObject)
      scaledValue += 1
      CS101_ASDU_addInformationObject(newAsdu, io)
      InformationObject_destroy(io)
      #/* Add ASDU to slave event queue - don't release the ASDU afterwards!
      CS104_Slave_enqueueASDU(self.slave, newAsdu)
      CS101_ASDU_destroy(newAsdu)

  def stop(self):
    CS104_Slave_stop(self.slave)
    CS104_Slave_destroy(self.slave)

#test the class
if __name__== "__main__":
  srv = IEC60870_5_104_server()
  srv.start()

