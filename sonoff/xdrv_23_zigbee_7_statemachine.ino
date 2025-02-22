/*
  xdrv_23_zigbee.ino - zigbee support for Sonoff-Tasmota

  Copyright (C) 2019  Theo Arends and Stephan Hadinger

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef USE_ZIGBEE

// Status code used for ZigbeeStatus MQTT message
// Ex: {"ZigbeeStatus":{"Status": 3,"Message":"Configured, starting coordinator"}}
const uint8_t  ZIGBEE_STATUS_OK = 0;                    // Zigbee started and working
const uint8_t  ZIGBEE_STATUS_BOOT = 1;                  // CC2530 booting
const uint8_t  ZIGBEE_STATUS_RESET_CONF = 2;            // Resetting CC2530 configuration
const uint8_t  ZIGBEE_STATUS_STARTING = 3;              // Starting CC2530 as coordinator
const uint8_t  ZIGBEE_STATUS_PERMITJOIN_CLOSE = 20;     // Disable PermitJoin
const uint8_t  ZIGBEE_STATUS_PERMITJOIN_OPEN_60 = 21;   // Enable PermitJoin for 60 seconds
const uint8_t  ZIGBEE_STATUS_PERMITJOIN_OPEN_XX = 22;   // Enable PermitJoin until next boot
const uint8_t  ZIGBEE_STATUS_DEVICE_ANNOUNCE = 30;      // Device announces its address
const uint8_t  ZIGBEE_STATUS_NODE_DESC = 31;            // Node descriptor
const uint8_t  ZIGBEE_STATUS_ACTIVE_EP = 32;            // Endpoints descriptor
const uint8_t  ZIGBEE_STATUS_SIMPLE_DESC = 33;          // Simple Descriptor (clusters)
const uint8_t  ZIGBEE_STATUS_CC_VERSION = 50;           // Status: CC2530 ZNP Version
const uint8_t  ZIGBEE_STATUS_CC_INFO = 51;              // Status: CC2530 Device Configuration
const uint8_t  ZIGBEE_STATUS_UNSUPPORTED_VERSION = 98;  // Unsupported ZNP version
const uint8_t  ZIGBEE_STATUS_ABORT = 99;                // Fatal error, Zigbee not working

typedef int32_t (*ZB_Func)(uint8_t value);
typedef int32_t (*ZB_RecvMsgFunc)(int32_t res, const class SBuffer &buf);

typedef union Zigbee_Instruction {
  struct {
    uint8_t  i;      // instruction
    uint8_t  d8;     // 8 bits data
    uint16_t d16;    // 16 bits data
  } i;
  const void *p;              // pointer
  // const void *m;           // for type checking only, message
  // const ZB_Func f;
  // const ZB_RecvMsgFunc fr;
} Zigbee_Instruction;
//
// Zigbee_Instruction z1 = { .i = {1,2,3}};
// Zigbee_Instruction z3 = { .p = nullptr };

typedef struct Zigbee_Instruction_Type {
  uint8_t instr;
  uint8_t data;
} Zigbee_Instruction_Type;

enum Zigbee_StateMachine_Instruction_Set {
  // 2 bytes instructions
  ZGB_INSTR_4_BYTES = 0,
  ZGB_INSTR_NOOP = 0,                   // do nothing
  ZGB_INSTR_LABEL,                      // define a label
  ZGB_INSTR_GOTO,                       // goto label
  ZGB_INSTR_ON_ERROR_GOTO,              // goto label if error
  ZGB_INSTR_ON_TIMEOUT_GOTO,            // goto label if timeout
  ZGB_INSTR_WAIT,                       // wait for x ms (in chunks of 100ms)
  ZGB_INSTR_WAIT_FOREVER,               // wait forever but state machine still active
  ZGB_INSTR_STOP,                       // stop state machine with optional error code

  // 6 bytes instructions
  ZGB_INSTR_8_BYTES = 0x80,
  ZGB_INSTR_CALL = 0x80,                // call a function
  ZGB_INSTR_LOG,                        // log a message, if more detailed logging required, call a function
  ZGB_INSTR_MQTT_STATUS,                // send MQTT status string with code
  ZGB_INSTR_SEND,                       // send a ZNP message
  ZGB_INSTR_WAIT_UNTIL,                 // wait until the specified message is received, ignore all others
  ZGB_INSTR_WAIT_RECV,                  // wait for a message according to the filter
  ZGB_ON_RECV_UNEXPECTED,               // function to handle unexpected messages, or nullptr

  // 10 bytes instructions
  ZGB_INSTR_12_BYTES = 0xF0,
  ZGB_INSTR_WAIT_RECV_CALL,             // wait for a filtered message and call function upon receive
};

#define ZI_NOOP()           { .i = { ZGB_INSTR_NOOP,   0x00, 0x0000} },
#define ZI_LABEL(x)         { .i = { ZGB_INSTR_LABEL,  (x),  0x0000} },
#define ZI_GOTO(x)          { .i = { ZGB_INSTR_GOTO,   (x),  0x0000} },
#define ZI_ON_ERROR_GOTO(x) { .i = { ZGB_INSTR_ON_ERROR_GOTO, (x), 0x0000} },
#define ZI_ON_TIMEOUT_GOTO(x) { .i = { ZGB_INSTR_ON_TIMEOUT_GOTO, (x), 0x0000} },
#define ZI_WAIT(x)          { .i = { ZGB_INSTR_WAIT,   0x00, (x)} },
#define ZI_WAIT_FOREVER()   { .i = { ZGB_INSTR_WAIT_FOREVER, 0x00, 0x0000} },
#define ZI_STOP(x)          { .i = { ZGB_INSTR_STOP,   (x), 0x0000} },

#define ZI_CALL(f, x)       { .i = { ZGB_INSTR_CALL, (x), 0x0000} }, { .p = (const void*)(f) },
#define ZI_LOG(x, m)        { .i = { ZGB_INSTR_LOG,    (x), 0x0000 } }, { .p = ((const void*)(m)) },
#define ZI_MQTT_STATUS(x, m) { .i = { ZGB_INSTR_MQTT_STATUS,    (x), 0x0000 } }, { .p = ((const void*)(m)) },
#define ZI_ON_RECV_UNEXPECTED(f) { .i = { ZGB_ON_RECV_UNEXPECTED, 0x00, 0x0000} }, { .p = (const void*)(f) },
#define ZI_SEND(m)          { .i = { ZGB_INSTR_SEND, sizeof(m), 0x0000} }, { .p = (const void*)(m) },
#define ZI_WAIT_RECV(x, m)  { .i = { ZGB_INSTR_WAIT_RECV, sizeof(m), (x)} }, { .p = (const void*)(m) },
#define ZI_WAIT_UNTIL(x, m) { .i = { ZGB_INSTR_WAIT_UNTIL, sizeof(m), (x)} }, { .p = (const void*)(m) },
#define ZI_WAIT_RECV_FUNC(x, m, f) { .i = { ZGB_INSTR_WAIT_RECV_CALL, sizeof(m), (x)} }, { .p = (const void*)(m) }, { .p = (const void*)(f) },

// Labels used in the State Machine -- internal only
const uint8_t  ZIGBEE_LABEL_START = 10;   // Start ZNP
const uint8_t  ZIGBEE_LABEL_READY = 20;   // goto label 20 for main loop
const uint8_t  ZIGBEE_LABEL_MAIN_LOOP = 21;   // main loop
const uint8_t  ZIGBEE_LABEL_PERMIT_JOIN_CLOSE = 30;   // disable permit join
const uint8_t  ZIGBEE_LABEL_PERMIT_JOIN_OPEN_60 = 31;    // enable permit join for 60 seconds
const uint8_t  ZIGBEE_LABEL_PERMIT_JOIN_OPEN_XX = 32;    // enable permit join for 60 seconds
// errors
const uint8_t  ZIGBEE_LABEL_ABORT = 99;   // goto label 99 in case of fatal error
const uint8_t  ZIGBEE_LABEL_UNSUPPORTED_VERSION = 98;  // Unsupported ZNP version

struct ZigbeeStatus {
  bool active = true;                 // is Zigbee active for this device, i.e. GPIOs configured
  bool state_machine = false;		      // the state machine is running
  bool state_waiting = false;         // the state machine is waiting for external event or timeout
  bool state_no_timeout = false;      // the current wait loop does not generate a timeout but only continues running
  bool ready = false;								  // cc2530 initialization is complet, ready to operate
  uint8_t on_error_goto = ZIGBEE_LABEL_ABORT;         // on error goto label, 99 default to abort
  uint8_t on_timeout_goto = ZIGBEE_LABEL_ABORT;       // on timeout goto label, 99 default to abort
  int16_t pc = 0;                     // program counter, -1 means abort
  uint32_t next_timeout = 0;          // millis for the next timeout

  uint8_t        *recv_filter = nullptr;        // receive filter message
  bool            recv_until = false;           // ignore all messages until the received frame fully matches
  size_t          recv_filter_len = 0;
  ZB_RecvMsgFunc recv_func = nullptr;          // function to call when message is expected
  ZB_RecvMsgFunc recv_unexpected = nullptr;    // function called when unexpected message is received

  bool init_phase = true;             // initialization phase, before accepting zigbee traffic
};
struct ZigbeeStatus zigbee;

SBuffer *zigbee_buffer = nullptr;

/*********************************************************************************************\
 * State Machine
\*********************************************************************************************/

#define Z_B0(a)            (uint8_t)( ((a)      ) & 0xFF )
#define Z_B1(a)            (uint8_t)( ((a) >>  8) & 0xFF )
#define Z_B2(a)            (uint8_t)( ((a) >> 16) & 0xFF )
#define Z_B3(a)            (uint8_t)( ((a) >> 24) & 0xFF )
#define Z_B4(a)            (uint8_t)( ((a) >> 32) & 0xFF )
#define Z_B5(a)            (uint8_t)( ((a) >> 40) & 0xFF )
#define Z_B6(a)            (uint8_t)( ((a) >> 48) & 0xFF )
#define Z_B7(a)            (uint8_t)( ((a) >> 56) & 0xFF )
// Macro to define message to send and receive
#define ZBM(n, x...) const uint8_t n[] PROGMEM = { x };

#define USE_ZIGBEE_CHANNEL_MASK (1 << (USE_ZIGBEE_CHANNEL))

// ZBS_* Zigbee Send
// ZBR_* Zigbee Recv
ZBM(ZBS_RESET, Z_AREQ | Z_SYS, SYS_RESET, 0x00 )        	  // 410001 SYS_RESET_REQ Hardware reset
ZBM(ZBR_RESET, Z_AREQ | Z_SYS, SYS_RESET_IND )              // 4180 SYS_RESET_REQ Hardware reset response

ZBM(ZBS_VERSION, Z_SREQ | Z_SYS, SYS_VERSION )              // 2102 Z_SYS:version
ZBM(ZBR_VERSION, Z_SRSP | Z_SYS, SYS_VERSION )              // 6102 Z_SYS:version

// Check if ZNP_HAS_CONFIGURED is set
ZBM(ZBS_ZNPHC, Z_SREQ | Z_SYS, SYS_OSAL_NV_READ, ZNP_HAS_CONFIGURED & 0xFF, ZNP_HAS_CONFIGURED >> 8, 0x00 /* offset */ )  // 2108000F00 - 6108000155
ZBM(ZBR_ZNPHC, Z_SRSP | Z_SYS, SYS_OSAL_NV_READ, Z_Success, 0x01 /* len */, 0x55)   // 6108000155
// If not set, the response is 61-08-02-00 = Z_SRSP | Z_SYS, SYS_OSAL_NV_READ, Z_InvalidParameter, 0x00 /* len */

ZBM(ZBS_PAN, Z_SREQ | Z_SAPI, SAPI_READ_CONFIGURATION, CONF_PANID )				// 260483
ZBM(ZBR_PAN, Z_SRSP | Z_SAPI, SAPI_READ_CONFIGURATION, Z_Success, CONF_PANID, 0x02 /* len */,
              Z_B0(USE_ZIGBEE_PANID), Z_B1(USE_ZIGBEE_PANID) )				// 6604008302xxxx

ZBM(ZBS_EXTPAN, Z_SREQ | Z_SAPI, SAPI_READ_CONFIGURATION, CONF_EXTENDED_PAN_ID )				// 26042D
ZBM(ZBR_EXTPAN, Z_SRSP | Z_SAPI, SAPI_READ_CONFIGURATION, Z_Success, CONF_EXTENDED_PAN_ID,
                0x08 /* len */,
                Z_B0(USE_ZIGBEE_EXTPANID), Z_B1(USE_ZIGBEE_EXTPANID), Z_B2(USE_ZIGBEE_EXTPANID), Z_B3(USE_ZIGBEE_EXTPANID),
                Z_B4(USE_ZIGBEE_EXTPANID), Z_B5(USE_ZIGBEE_EXTPANID), Z_B6(USE_ZIGBEE_EXTPANID), Z_B7(USE_ZIGBEE_EXTPANID),
                )				// 6604002D08xxxxxxxxxxxxxxxx

ZBM(ZBS_CHANN, Z_SREQ | Z_SAPI, SAPI_READ_CONFIGURATION, CONF_CHANLIST )				// 260484
ZBM(ZBR_CHANN, Z_SRSP | Z_SAPI, SAPI_READ_CONFIGURATION, Z_Success, CONF_CHANLIST,
               0x04 /* len */,
               Z_B0(USE_ZIGBEE_CHANNEL_MASK), Z_B1(USE_ZIGBEE_CHANNEL_MASK), Z_B2(USE_ZIGBEE_CHANNEL_MASK), Z_B3(USE_ZIGBEE_CHANNEL_MASK),
               )				// 6604008404xxxxxxxx

ZBM(ZBS_PFGK, Z_SREQ | Z_SAPI, SAPI_READ_CONFIGURATION, CONF_PRECFGKEY )				// 260462
ZBM(ZBR_PFGK, Z_SRSP | Z_SAPI, SAPI_READ_CONFIGURATION, Z_Success, CONF_PRECFGKEY,
              0x10 /* len */,
              Z_B0(USE_ZIGBEE_PRECFGKEY_L), Z_B1(USE_ZIGBEE_PRECFGKEY_L), Z_B2(USE_ZIGBEE_PRECFGKEY_L), Z_B3(USE_ZIGBEE_PRECFGKEY_L),
              Z_B4(USE_ZIGBEE_PRECFGKEY_L), Z_B5(USE_ZIGBEE_PRECFGKEY_L), Z_B6(USE_ZIGBEE_PRECFGKEY_L), Z_B7(USE_ZIGBEE_PRECFGKEY_L),
              Z_B0(USE_ZIGBEE_PRECFGKEY_H), Z_B1(USE_ZIGBEE_PRECFGKEY_H), Z_B2(USE_ZIGBEE_PRECFGKEY_H), Z_B3(USE_ZIGBEE_PRECFGKEY_H),
              Z_B4(USE_ZIGBEE_PRECFGKEY_H), Z_B5(USE_ZIGBEE_PRECFGKEY_H), Z_B6(USE_ZIGBEE_PRECFGKEY_H), Z_B7(USE_ZIGBEE_PRECFGKEY_H),
              /*0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F,
              0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0D*/ )				// 660400621001030507090B0D0F00020406080A0C0D

ZBM(ZBS_PFGKEN, Z_SREQ | Z_SAPI, SAPI_READ_CONFIGURATION, CONF_PRECFGKEYS_ENABLE )				// 260463
ZBM(ZBR_PFGKEN, Z_SRSP | Z_SAPI, SAPI_READ_CONFIGURATION, Z_Success, CONF_PRECFGKEYS_ENABLE,
                0x01 /* len */, 0x00 )				// 660400630100

// commands to "format" the device
// Write configuration - write success
ZBM(ZBR_W_OK, Z_SRSP | Z_SAPI, SAPI_WRITE_CONFIGURATION, Z_Success )				// 660500 - Write Configuration
ZBM(ZBR_WNV_OK, Z_SRSP | Z_SYS, SYS_OSAL_NV_WRITE, Z_Success )				// 610900 - NV Write

// Factory reset
ZBM(ZBS_FACTRES, Z_SREQ | Z_SAPI, SAPI_WRITE_CONFIGURATION, CONF_STARTUP_OPTION, 0x01 /* len */, 0x02 )				// 2605030102
// Write PAN ID
ZBM(ZBS_W_PAN, Z_SREQ | Z_SAPI, SAPI_WRITE_CONFIGURATION, CONF_PANID, 0x02 /* len */, Z_B0(USE_ZIGBEE_PANID), Z_B1(USE_ZIGBEE_PANID)  )				// 26058302xxxx
// Write EXT PAN ID
ZBM(ZBS_W_EXTPAN, Z_SREQ | Z_SAPI, SAPI_WRITE_CONFIGURATION, CONF_EXTENDED_PAN_ID, 0x08 /* len */,
                  Z_B0(USE_ZIGBEE_EXTPANID), Z_B1(USE_ZIGBEE_EXTPANID), Z_B2(USE_ZIGBEE_EXTPANID), Z_B3(USE_ZIGBEE_EXTPANID),
                  Z_B4(USE_ZIGBEE_EXTPANID), Z_B5(USE_ZIGBEE_EXTPANID), Z_B6(USE_ZIGBEE_EXTPANID), Z_B7(USE_ZIGBEE_EXTPANID)
                  ) // 26052D086263151D004B1200
// Write Channel ID
ZBM(ZBS_W_CHANN, Z_SREQ | Z_SAPI, SAPI_WRITE_CONFIGURATION, CONF_CHANLIST, 0x04 /* len */,
                Z_B0(USE_ZIGBEE_CHANNEL_MASK), Z_B1(USE_ZIGBEE_CHANNEL_MASK), Z_B2(USE_ZIGBEE_CHANNEL_MASK), Z_B3(USE_ZIGBEE_CHANNEL_MASK),
                /*0x00, 0x08, 0x00, 0x00*/ )				// 26058404xxxxxxxx
// Write Logical Type = 00 = coordinator
ZBM(ZBS_W_LOGTYP, Z_SREQ | Z_SAPI, SAPI_WRITE_CONFIGURATION, CONF_LOGICAL_TYPE, 0x01 /* len */, 0x00 )				// 2605870100
// Write precfgkey
ZBM(ZBS_W_PFGK, Z_SREQ | Z_SAPI, SAPI_WRITE_CONFIGURATION, CONF_PRECFGKEY,
                0x10 /* len */,
                Z_B0(USE_ZIGBEE_PRECFGKEY_L), Z_B1(USE_ZIGBEE_PRECFGKEY_L), Z_B2(USE_ZIGBEE_PRECFGKEY_L), Z_B3(USE_ZIGBEE_PRECFGKEY_L),
                Z_B4(USE_ZIGBEE_PRECFGKEY_L), Z_B5(USE_ZIGBEE_PRECFGKEY_L), Z_B6(USE_ZIGBEE_PRECFGKEY_L), Z_B7(USE_ZIGBEE_PRECFGKEY_L),
                Z_B0(USE_ZIGBEE_PRECFGKEY_H), Z_B1(USE_ZIGBEE_PRECFGKEY_H), Z_B2(USE_ZIGBEE_PRECFGKEY_H), Z_B3(USE_ZIGBEE_PRECFGKEY_H),
                Z_B4(USE_ZIGBEE_PRECFGKEY_H), Z_B5(USE_ZIGBEE_PRECFGKEY_H), Z_B6(USE_ZIGBEE_PRECFGKEY_H), Z_B7(USE_ZIGBEE_PRECFGKEY_H),
                /*0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F,
                0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0D*/ )				// 2605621001030507090B0D0F00020406080A0C0D
// Write precfgkey enable
ZBM(ZBS_W_PFGKEN, Z_SREQ | Z_SAPI, SAPI_WRITE_CONFIGURATION, CONF_PRECFGKEYS_ENABLE, 0x01 /* len */, 0x00 )				// 2605630100
// Write Security Mode
ZBM(ZBS_WNV_SECMODE, Z_SREQ | Z_SYS, SYS_OSAL_NV_WRITE, Z_B0(CONF_TCLK_TABLE_START), Z_B1(CONF_TCLK_TABLE_START),
                      0x00 /* offset */, 0x20 /* len */,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                      0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c,
                      0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x30, 0x39,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)				// 2109010100200FFFFFFFFFFFFFFFF5A6967426565416C6C69616E636530390000000000000000
// Write Z_ZDO Direct CB
ZBM(ZBS_W_ZDODCB, Z_SREQ | Z_SAPI, SAPI_WRITE_CONFIGURATION, CONF_ZDO_DIRECT_CB, 0x01 /* len */, 0x01 )				// 26058F0101
// NV Init ZNP Has Configured
ZBM(ZBS_WNV_INITZNPHC, Z_SREQ | Z_SYS, SYS_OSAL_NV_ITEM_INIT, ZNP_HAS_CONFIGURED & 0xFF, ZNP_HAS_CONFIGURED >> 8,
                       0x01, 0x00 /* InitLen 16 bits */, 0x01 /* len */, 0x00 )  // 2107000F01000100 - 610709
// Init succeeded
//ZBM(ZBR_WNV_INIT_OK, Z_SRSP | Z_SYS, SYS_OSAL_NV_ITEM_INIT, Z_Created )				// 610709 - NV Write
ZBM(ZBR_WNV_INIT_OK, Z_SRSP | Z_SYS, SYS_OSAL_NV_ITEM_INIT )				  // 6107xx, Success if 610700 or 610709 - NV Write

// Write ZNP Has Configured
ZBM(ZBS_WNV_ZNPHC, Z_SREQ | Z_SYS, SYS_OSAL_NV_WRITE, Z_B0(ZNP_HAS_CONFIGURED), Z_B1(ZNP_HAS_CONFIGURED),
                   0x00 /* offset */, 0x01 /* len */, 0x55 )				// 2109000F000155 - 610900
// Z_ZDO:startupFromApp
ZBM(ZBS_STARTUPFROMAPP, Z_SREQ | Z_ZDO, ZDO_STARTUP_FROM_APP, 100, 0 /* delay */)   // 25406400
ZBM(ZBR_STARTUPFROMAPP, Z_SRSP | Z_ZDO, ZDO_STARTUP_FROM_APP )   // 6540 + 01 for new network, 00 for exisitng network, 02 for error
ZBM(AREQ_STARTUPFROMAPP, Z_AREQ | Z_ZDO, ZDO_STATE_CHANGE_IND, ZDO_DEV_ZB_COORD )    // 45C009 + 08 = starting, 09 = started
// GetDeviceInfo
ZBM(ZBS_GETDEVICEINFO, Z_SREQ | Z_UTIL, Z_UTIL_GET_DEVICE_INFO )     // 2700
ZBM(ZBR_GETDEVICEINFO, Z_SRSP | Z_UTIL, Z_UTIL_GET_DEVICE_INFO, Z_Success )   // Ex= 6700.00.6263151D004B1200.0000.07.09.00
    // IEEE Adr (8 bytes) = 6263151D004B1200
    // Short Addr (2 bytes) = 0000
    // Device Type (1 byte) = 07 (coord?)
    // Device State (1 byte) = 09 (coordinator started)
    // NumAssocDevices (1 byte) = 00

// Read Pan ID
//ZBM(ZBS_READ_NV_PANID, Z_SREQ | Z_SYS, SYS_OSAL_NV_READ, PANID & 0xFF, PANID >> 8, 0x00 /* offset */ )  // 2108830000

// Z_ZDO:nodeDescReq
ZBM(ZBS_ZDO_NODEDESCREQ, Z_SREQ | Z_ZDO, ZDO_NODE_DESC_REQ, 0x00, 0x00 /* dst addr */, 0x00, 0x00 /* NWKAddrOfInterest */)    // 250200000000
ZBM(ZBR_ZDO_NODEDESCREQ, Z_SRSP | Z_ZDO, ZDO_NODE_DESC_REQ, Z_Success )   // 650200
// Async resp ex: 4582.0000.00.0000.00.40.8F.0000.50.A000.0100.A000.00
ZBM(AREQ_ZDO_NODEDESCRSP, Z_AREQ | Z_ZDO, ZDO_NODE_DESC_RSP)    // 4582
// SrcAddr (2 bytes) 0000
// Status (1 byte) 00 Success
// NwkAddr (2 bytes) 0000
// LogicalType (1 byte) - 00 Coordinator
// APSFlags (1 byte) - 40 0=APSFlags 4=NodeFreqBands
// MACCapabilityFlags (1 byte) - 8F ALL
// ManufacturerCode (2 bytes) - 0000
// MaxBufferSize (1 byte) - 50 NPDU
// MaxTransferSize (2 bytes) - A000 = 160
// ServerMask (2 bytes) - 0100 - Primary Trust Center
// MaxOutTransferSize (2 bytes) - A000 = 160
// DescriptorCapabilities (1 byte) - 00

// Z_ZDO:activeEpReq
ZBM(ZBS_ZDO_ACTIVEEPREQ, Z_SREQ | Z_ZDO, ZDO_ACTIVE_EP_REQ, 0x00, 0x00, 0x00, 0x00)  // 250500000000
ZBM(ZBR_ZDO_ACTIVEEPREQ, Z_SRSP | Z_ZDO, ZDO_ACTIVE_EP_REQ, Z_Success)  // 65050000
ZBM(ZBR_ZDO_ACTIVEEPRSP_NONE, Z_AREQ | Z_ZDO, ZDO_ACTIVE_EP_RSP, 0x00, 0x00 /* srcAddr */, Z_Success,
    0x00, 0x00 /* nwkaddr */, 0x00 /* activeepcount */)  // 45050000 - no Ep running
ZBM(ZBR_ZDO_ACTIVEEPRSP_OK, Z_AREQ | Z_ZDO, ZDO_ACTIVE_EP_RSP, 0x00, 0x00 /* srcAddr */, Z_Success,
    0x00, 0x00 /* nwkaddr */, 0x02 /* activeepcount */, 0x0B, 0x01 /* the actual endpoints */)  // 25050000 - no Ep running

// Z_AF:register profile:104, ep:01
ZBM(ZBS_AF_REGISTER01, Z_SREQ | Z_AF, AF_REGISTER, 0x01 /* endpoint */, Z_B0(Z_PROF_HA), Z_B1(Z_PROF_HA),    // 24000401050000000000
                        0x05, 0x00 /* AppDeviceId */, 0x00 /* AppDevVer */, 0x00 /* LatencyReq */,
                        0x00 /* AppNumInClusters */, 0x00 /* AppNumInClusters */)
ZBM(ZBR_AF_REGISTER,   Z_SRSP | Z_AF, AF_REGISTER, Z_Success)   // 640000
ZBM(ZBS_AF_REGISTER0B, Z_SREQ | Z_AF, AF_REGISTER, 0x0B /* endpoint */, Z_B0(Z_PROF_HA), Z_B1(Z_PROF_HA),    // 2400040B050000000000
                        0x05, 0x00 /* AppDeviceId */, 0x00 /* AppDevVer */, 0x00 /* LatencyReq */,
                        0x00 /* AppNumInClusters */, 0x00 /* AppNumInClusters */)
// Z_ZDO:mgmtPermitJoinReq
ZBM(ZBS_PERMITJOINREQ_CLOSE, Z_SREQ | Z_ZDO, ZDO_MGMT_PERMIT_JOIN_REQ, 0x02 /* AddrMode */,   // 25360200000000
                              0x00, 0x00 /* DstAddr */, 0x00 /* Duration */, 0x00 /* TCSignificance */)
ZBM(ZBS_PERMITJOINREQ_OPEN_60, Z_SREQ | Z_ZDO, ZDO_MGMT_PERMIT_JOIN_REQ, 0x0F /* AddrMode */,   // 25360FFFFC3C00
                              0xFC, 0xFF /* DstAddr */, 60 /* Duration */, 0x00 /* TCSignificance */)
ZBM(ZBS_PERMITJOINREQ_OPEN_XX, Z_SREQ | Z_ZDO, ZDO_MGMT_PERMIT_JOIN_REQ, 0x0F /* AddrMode */,   // 25360FFFFCFF00
                              0xFC, 0xFF /* DstAddr */, 0xFF /* Duration */, 0x00 /* TCSignificance */)
ZBM(ZBR_PERMITJOINREQ, Z_SRSP | Z_ZDO, ZDO_MGMT_PERMIT_JOIN_REQ, Z_Success)    // 653600
ZBM(ZBR_PERMITJOIN_AREQ_CLOSE, Z_AREQ | Z_ZDO, ZDO_PERMIT_JOIN_IND, 0x00 /* Duration */)      // 45CB00
ZBM(ZBR_PERMITJOIN_AREQ_OPEN_60, Z_AREQ | Z_ZDO, ZDO_PERMIT_JOIN_IND, 60 /* Duration */)      // 45CB3C
ZBM(ZBR_PERMITJOIN_AREQ_OPEN_FF, Z_AREQ | Z_ZDO, ZDO_PERMIT_JOIN_IND, 0xFF /* Duration */)    // 45CBFF
ZBM(ZBR_PERMITJOIN_AREQ_RSP,  Z_AREQ | Z_ZDO, ZDO_MGMT_PERMIT_JOIN_RSP, 0x00, 0x00 /* srcAddr*/, Z_Success )   // 45B6000000

static const Zigbee_Instruction zb_prog[] PROGMEM = {
  ZI_LABEL(0)
    ZI_NOOP()
    ZI_ON_ERROR_GOTO(ZIGBEE_LABEL_ABORT)
    ZI_ON_TIMEOUT_GOTO(ZIGBEE_LABEL_ABORT)
    ZI_ON_RECV_UNEXPECTED(&Z_Recv_Default)
    ZI_WAIT(10000)                             // wait for 10 seconds for Tasmota to stabilize
    ZI_ON_ERROR_GOTO(50)

    ZI_MQTT_STATUS(ZIGBEE_STATUS_BOOT, "Booting")
    //ZI_LOG(LOG_LEVEL_INFO, "ZIG: rebooting device")
    ZI_SEND(ZBS_RESET)                        // reboot cc2530 just in case we rebooted ESP8266 but not cc2530
    ZI_WAIT_RECV(5000, ZBR_RESET)             // timeout 5s
    ZI_WAIT(100)
    ZI_LOG(LOG_LEVEL_INFO, "ZIG: checking device configuration")
    ZI_SEND(ZBS_ZNPHC)                        // check value of ZNP Has Configured
    ZI_WAIT_RECV(2000, ZBR_ZNPHC)
    ZI_SEND(ZBS_VERSION)                      // check ZNP software version
    ZI_WAIT_RECV_FUNC(2000, ZBR_VERSION, &Z_ReceiveCheckVersion)  // Check version
    ZI_SEND(ZBS_PAN)                          // check PAN ID
    ZI_WAIT_RECV(1000, ZBR_PAN)
    ZI_SEND(ZBS_EXTPAN)                       // check EXT PAN ID
    ZI_WAIT_RECV(1000, ZBR_EXTPAN)
    ZI_SEND(ZBS_CHANN)                        // check CHANNEL
    ZI_WAIT_RECV(1000, ZBR_CHANN)
    ZI_SEND(ZBS_PFGK)                         // check PFGK
    ZI_WAIT_RECV(1000, ZBR_PFGK)
    ZI_SEND(ZBS_PFGKEN)                       // check PFGKEN
    ZI_WAIT_RECV(1000, ZBR_PFGKEN)
    //ZI_LOG(LOG_LEVEL_INFO, "ZIG: zigbee configuration ok")
    // all is good, we can start

  ZI_LABEL(ZIGBEE_LABEL_START)                // START ZNP App
    ZI_MQTT_STATUS(ZIGBEE_STATUS_STARTING, "Configured, starting coordinator")
    //ZI_CALL(&Z_State_Ready, 1)                // Now accept incoming messages
    ZI_ON_ERROR_GOTO(ZIGBEE_LABEL_ABORT)
    // Z_ZDO:startupFromApp
    //ZI_LOG(LOG_LEVEL_INFO, "ZIG: starting zigbee coordinator")
ZI_SEND(ZBS_STARTUPFROMAPP)                       // start coordinator
    ZI_WAIT_RECV(2000, ZBR_STARTUPFROMAPP)        // wait for sync ack of command
    ZI_WAIT_UNTIL(5000, AREQ_STARTUPFROMAPP)      // wait for async message that coordinator started
    ZI_SEND(ZBS_GETDEVICEINFO)                    // GetDeviceInfo
    ZI_WAIT_RECV_FUNC(2000, ZBR_GETDEVICEINFO, &Z_ReceiveDeviceInfo)
    //ZI_WAIT_RECV(2000, ZBR_GETDEVICEINFO)         // TODO memorize info
    ZI_SEND(ZBS_ZDO_NODEDESCREQ)                  // Z_ZDO:nodeDescReq
    ZI_WAIT_RECV(1000, ZBR_ZDO_NODEDESCREQ)
    ZI_WAIT_UNTIL(5000, AREQ_ZDO_NODEDESCRSP)
    ZI_SEND(ZBS_ZDO_ACTIVEEPREQ)                  // Z_ZDO:activeEpReq
    ZI_WAIT_RECV(1000, ZBR_ZDO_ACTIVEEPREQ)
    ZI_WAIT_UNTIL(1000, ZBR_ZDO_ACTIVEEPRSP_NONE)
    ZI_SEND(ZBS_AF_REGISTER01)                    // Z_AF register for endpoint 01, profile 0x0104 Home Automation
    ZI_WAIT_RECV(1000, ZBR_AF_REGISTER)
    ZI_SEND(ZBS_AF_REGISTER0B)                    // Z_AF register for endpoint 0B, profile 0x0104 Home Automation
    ZI_WAIT_RECV(1000, ZBR_AF_REGISTER)
    // Z_ZDO:nodeDescReq ?? Is is useful to redo it?  TODO
    // redo Z_ZDO:activeEpReq to check that Ep are available
    ZI_SEND(ZBS_ZDO_ACTIVEEPREQ)                  // Z_ZDO:activeEpReq
    ZI_WAIT_RECV(1000, ZBR_ZDO_ACTIVEEPREQ)
    ZI_WAIT_UNTIL(1000, ZBR_ZDO_ACTIVEEPRSP_OK)
    ZI_SEND(ZBS_PERMITJOINREQ_CLOSE)              // Closing the Permit Join
    ZI_WAIT_RECV(1000, ZBR_PERMITJOINREQ)
    ZI_WAIT_UNTIL(1000, ZBR_PERMITJOIN_AREQ_RSP)  // not sure it's useful
    //ZI_WAIT_UNTIL(500, ZBR_PERMITJOIN_AREQ_CLOSE)
    //ZI_SEND(ZBS_PERMITJOINREQ_OPEN_XX)               // Opening Permit Join, normally through command
    //ZI_WAIT_RECV(1000, ZBR_PERMITJOINREQ)
    //ZI_WAIT_UNTIL(1000, ZBR_PERMITJOIN_AREQ_RSP)  // not sure it's useful
    //ZI_WAIT_UNTIL(500, ZBR_PERMITJOIN_AREQ_OPEN_FF)

  ZI_LABEL(ZIGBEE_LABEL_READY)
    ZI_MQTT_STATUS(ZIGBEE_STATUS_OK, "Started")
    ZI_LOG(LOG_LEVEL_INFO, "ZIG: zigbee device ready, listening...")
    ZI_CALL(&Z_State_Ready, 1)                    // Now accept incoming messages
  ZI_LABEL(ZIGBEE_LABEL_MAIN_LOOP)
    ZI_WAIT_FOREVER()
    ZI_GOTO(ZIGBEE_LABEL_READY)

  ZI_LABEL(ZIGBEE_LABEL_PERMIT_JOIN_CLOSE)
    //ZI_MQTT_STATUS(ZIGBEE_STATUS_PERMITJOIN_CLOSE, "Disable Pairing mode")
    ZI_SEND(ZBS_PERMITJOINREQ_CLOSE)              // Closing the Permit Join
    ZI_WAIT_RECV(1000, ZBR_PERMITJOINREQ)
    //ZI_WAIT_UNTIL(1000, ZBR_PERMITJOIN_AREQ_RSP)  // not sure it's useful
    //ZI_WAIT_UNTIL(500, ZBR_PERMITJOIN_AREQ_CLOSE)
    ZI_GOTO(ZIGBEE_LABEL_MAIN_LOOP)

  ZI_LABEL(ZIGBEE_LABEL_PERMIT_JOIN_OPEN_60)
    //ZI_MQTT_STATUS(ZIGBEE_STATUS_PERMITJOIN_OPEN_60, "Enable Pairing mode for 60 seconds")
    ZI_SEND(ZBS_PERMITJOINREQ_OPEN_60)
    ZI_WAIT_RECV(1000, ZBR_PERMITJOINREQ)
    //ZI_WAIT_UNTIL(1000, ZBR_PERMITJOIN_AREQ_RSP)  // not sure it's useful
    //ZI_WAIT_UNTIL(500, ZBR_PERMITJOIN_AREQ_OPEN_60)
    ZI_GOTO(ZIGBEE_LABEL_MAIN_LOOP)

  ZI_LABEL(ZIGBEE_LABEL_PERMIT_JOIN_OPEN_XX)
    //ZI_MQTT_STATUS(ZIGBEE_STATUS_PERMITJOIN_OPEN_XX, "Enable Pairing mode until next boot")
    ZI_SEND(ZBS_PERMITJOINREQ_OPEN_XX)
    ZI_WAIT_RECV(1000, ZBR_PERMITJOINREQ)
    //ZI_WAIT_UNTIL(1000, ZBR_PERMITJOIN_AREQ_RSP)  // not sure it's useful
    //ZI_WAIT_UNTIL(500, ZBR_PERMITJOIN_AREQ_OPEN_FF)
    ZI_GOTO(ZIGBEE_LABEL_MAIN_LOOP)

  ZI_LABEL(50)                                    // reformat device
    ZI_MQTT_STATUS(ZIGBEE_STATUS_RESET_CONF, "Reseting configuration")
    //ZI_LOG(LOG_LEVEL_INFO, "ZIG: zigbee bad configuration of device, doing a factory reset")
    ZI_ON_ERROR_GOTO(ZIGBEE_LABEL_ABORT)
    ZI_SEND(ZBS_FACTRES)                          // factory reset
    ZI_WAIT_RECV(1000, ZBR_W_OK)
    ZI_SEND(ZBS_RESET)                            // reset device
    ZI_WAIT_RECV(5000, ZBR_RESET)
    ZI_SEND(ZBS_W_PAN)                            // write PAN ID
    ZI_WAIT_RECV(1000, ZBR_W_OK)
    ZI_SEND(ZBS_W_EXTPAN)                         // write EXT PAN ID
    ZI_WAIT_RECV(1000, ZBR_W_OK)
    ZI_SEND(ZBS_W_CHANN)                          // write CHANNEL
    ZI_WAIT_RECV(1000, ZBR_W_OK)
    ZI_SEND(ZBS_W_LOGTYP)                         // write Logical Type = coordinator
    ZI_WAIT_RECV(1000, ZBR_W_OK)
    ZI_SEND(ZBS_W_PFGK)                           // write PRECFGKEY
    ZI_WAIT_RECV(1000, ZBR_W_OK)
    ZI_SEND(ZBS_W_PFGKEN)                         // write PRECFGKEY Enable
    ZI_WAIT_RECV(1000, ZBR_W_OK)
    ZI_SEND(ZBS_WNV_SECMODE)                      // write Security Mode
    ZI_WAIT_RECV(1000, ZBR_WNV_OK)
    ZI_SEND(ZBS_W_ZDODCB)                         // write Z_ZDO Direct CB
    ZI_WAIT_RECV(1000, ZBR_W_OK)
    // Now mark the device as ready, writing 0x55 in memory slot 0x0F00
    ZI_SEND(ZBS_WNV_INITZNPHC)                    // Init NV ZNP Has Configured
    ZI_WAIT_RECV_FUNC(1000, ZBR_WNV_INIT_OK, &Z_CheckNVWrite)
    ZI_SEND(ZBS_WNV_ZNPHC)                        // Write NV ZNP Has Configured
    ZI_WAIT_RECV(1000, ZBR_WNV_OK)

    //ZI_LOG(LOG_LEVEL_INFO, "ZIG: zigbee device reconfigured")
    ZI_GOTO(ZIGBEE_LABEL_START)

  ZI_LABEL(ZIGBEE_LABEL_UNSUPPORTED_VERSION)
    ZI_MQTT_STATUS(ZIGBEE_STATUS_UNSUPPORTED_VERSION, "Only ZNP 1.2 is currently supported")
    ZI_GOTO(ZIGBEE_LABEL_ABORT)

  ZI_LABEL(ZIGBEE_LABEL_ABORT)                    // Label 99: abort
    ZI_MQTT_STATUS(ZIGBEE_STATUS_ABORT, "Abort")
    ZI_LOG(LOG_LEVEL_ERROR, "ZIG: Abort")
    ZI_STOP(ZIGBEE_LABEL_ABORT)
};

uint8_t ZigbeeGetInstructionSize(uint8_t instr) {   // in Zigbee_Instruction lines (words)
  if (instr >= ZGB_INSTR_12_BYTES) {
    return 3;
  } else if (instr >= ZGB_INSTR_8_BYTES) {
    return 2;
  } else {
    return 1;
  }
}

void ZigbeeGotoLabel(uint8_t label) {
  // look for the label scanning entire code
  uint16_t goto_pc = 0xFFFF;    // 0xFFFF means not found
  uint8_t  cur_instr = 0;
  uint8_t  cur_d8 = 0;
  uint8_t  cur_instr_len = 1;       // size of current instruction in words

  for (uint32_t i = 0; i < sizeof(zb_prog)/sizeof(zb_prog[0]); i += cur_instr_len) {
    const Zigbee_Instruction *cur_instr_line = &zb_prog[i];
    cur_instr = pgm_read_byte(&cur_instr_line->i.i);
    cur_d8    = pgm_read_byte(&cur_instr_line->i.d8);
    //AddLog_P2(LOG_LEVEL_DEBUG_MORE, PSTR("ZGB GOTO: pc %d instr %d"), i, cur_instr);

    if (ZGB_INSTR_LABEL == cur_instr) {
      //AddLog_P2(LOG_LEVEL_DEBUG_MORE, PSTR("ZIG: found label %d at pc %d"), cur_d8, i);
      if (label == cur_d8) {
        // label found, goto to this pc
        zigbee.pc = i;
        zigbee.state_machine = true;
        zigbee.state_waiting = false;
        return;
      }
    }
    // get instruction length
    cur_instr_len = ZigbeeGetInstructionSize(cur_instr);
  }

  // no label found, abort
  AddLog_P2(LOG_LEVEL_ERROR, PSTR("ZIG: Goto label not found, label=%d pc=%d"), label, zigbee.pc);
  if (ZIGBEE_LABEL_ABORT != label) {
    // if not already looking for ZIGBEE_LABEL_ABORT, goto ZIGBEE_LABEL_ABORT
    ZigbeeGotoLabel(ZIGBEE_LABEL_ABORT);
  } else {
    AddLog_P2(LOG_LEVEL_ERROR, PSTR("ZIG: Label Abort (%d) not present, aborting Zigbee"), ZIGBEE_LABEL_ABORT);
    zigbee.state_machine = false;
    zigbee.active = false;
  }
}

void ZigbeeStateMachine_Run(void) {
  uint8_t cur_instr = 0;
  uint8_t cur_d8 = 0;
  uint16_t cur_d16 = 0;
  const void*   cur_ptr1 = nullptr;
  const void*   cur_ptr2 = nullptr;
  uint32_t now = millis();

  if (zigbee.state_waiting) {     // state machine is waiting for external event or timeout
    // checking if timeout expired
    if ((zigbee.next_timeout) && (now > zigbee.next_timeout)) {    // if next_timeout == 0 then wait forever
      //AddLog_P2(LOG_LEVEL_INFO, PSTR("ZIG: timeout occured pc=%d"), zigbee.pc);
      if (!zigbee.state_no_timeout) {
        AddLog_P2(LOG_LEVEL_INFO, PSTR("ZIG: timeout, goto label %d"), zigbee.on_timeout_goto);
        ZigbeeGotoLabel(zigbee.on_timeout_goto);
      } else {
        zigbee.state_waiting = false;     // simply stop waiting
      }
    }
  }

  while ((zigbee.state_machine) && (!zigbee.state_waiting)) {
    // reinit receive filters and functions (they only work for a single instruction)
    zigbee.recv_filter = nullptr;
    zigbee.recv_func   = nullptr;
    zigbee.recv_until  = false;
    zigbee.state_no_timeout = false;   // reset the no_timeout for next instruction

    if (zigbee.pc > (sizeof(zb_prog)/sizeof(zb_prog[0]))) {
      AddLog_P2(LOG_LEVEL_ERROR, PSTR("ZIG: Invalid pc: %d, aborting"), zigbee.pc);
      zigbee.pc = -1;
    }
    if (zigbee.pc < 0) {
      zigbee.state_machine = false;
      return;
    }

    // load current instruction details
    AddLog_P2(LOG_LEVEL_DEBUG_MORE, PSTR("ZIG: Executing instruction pc=%d"), zigbee.pc);
    const Zigbee_Instruction *cur_instr_line = &zb_prog[zigbee.pc];
    cur_instr = pgm_read_byte(&cur_instr_line->i.i);
    cur_d8    = pgm_read_byte(&cur_instr_line->i.d8);
    cur_d16   = pgm_read_word(&cur_instr_line->i.d16);
    if (cur_instr >= ZGB_INSTR_8_BYTES) {
      cur_instr_line++;
      cur_ptr1 = cur_instr_line->p;
    }
    if (cur_instr >= ZGB_INSTR_12_BYTES) {
      cur_instr_line++;
      cur_ptr2 = cur_instr_line->p;
    }

    zigbee.pc += ZigbeeGetInstructionSize(cur_instr);               // move pc to next instruction, before any goto

    switch (cur_instr) {
      case ZGB_INSTR_NOOP:
      case ZGB_INSTR_LABEL:   // do nothing
        break;
      case ZGB_INSTR_GOTO:
        ZigbeeGotoLabel(cur_d8);
        break;
      case ZGB_INSTR_ON_ERROR_GOTO:
        zigbee.on_error_goto = cur_d8;
        break;
      case ZGB_INSTR_ON_TIMEOUT_GOTO:
        zigbee.on_timeout_goto = cur_d8;
        break;
      case ZGB_INSTR_WAIT:
        zigbee.next_timeout = now + cur_d16;
        zigbee.state_waiting = true;
        zigbee.state_no_timeout = true;    // do not generate a timeout error when waiting is done
        break;
      case ZGB_INSTR_WAIT_FOREVER:
        zigbee.next_timeout = 0;
        zigbee.state_waiting = true;
        //zigbee.state_no_timeout = true;    // do not generate a timeout error when waiting is done
        break;
      case ZGB_INSTR_STOP:
        zigbee.state_machine = false;
        if (cur_d8) {
          AddLog_P2(LOG_LEVEL_ERROR, PSTR("ZIG: Stopping (%d)"), cur_d8);
        }
        break;
      case ZGB_INSTR_CALL:
        if (cur_ptr1) {
          uint32_t res;
          res = (*((ZB_Func)cur_ptr1))(cur_d8);
          if (res > 0) {
            ZigbeeGotoLabel(res);
            continue;     // avoid incrementing PC after goto
          } else if (res == 0) {
            // do nothing
          } else if (res == -1) {
            // do nothing
          } else {
            ZigbeeGotoLabel(zigbee.on_error_goto);
            continue;
          }
        }
        break;
      case ZGB_INSTR_LOG:
        AddLog_P(cur_d8, (char*) cur_ptr1);
        break;
      case ZGB_INSTR_MQTT_STATUS:
        Response_P(PSTR("{\"" D_JSON_ZIGBEE_STATUS "\":{\"Status\":%d,\"Message\":\"%s\"}}"),
                          cur_d8, (char*) cur_ptr1);
      	MqttPublishPrefixTopic_P(RESULT_OR_TELE, PSTR(D_JSON_ZIGBEE_STATUS));
      	XdrvRulesProcess();
        break;
      case ZGB_INSTR_SEND:
        ZigbeeZNPSend((uint8_t*) cur_ptr1, cur_d8 /* len */);
        break;
      case ZGB_INSTR_WAIT_UNTIL:
        zigbee.recv_until = true;   // and reuse ZGB_INSTR_WAIT_RECV
      case ZGB_INSTR_WAIT_RECV:
        zigbee.recv_filter = (uint8_t *) cur_ptr1;
        zigbee.recv_filter_len = cur_d8; // len
        zigbee.next_timeout = now + cur_d16;
        zigbee.state_waiting = true;
        break;
      case ZGB_ON_RECV_UNEXPECTED:
        zigbee.recv_unexpected = (ZB_RecvMsgFunc) cur_ptr1;
        break;
      case ZGB_INSTR_WAIT_RECV_CALL:
        zigbee.recv_filter = (uint8_t *) cur_ptr1;
        zigbee.recv_filter_len = cur_d8; // len
        zigbee.recv_func   = (ZB_RecvMsgFunc)  cur_ptr2;
        zigbee.next_timeout = now + cur_d16;
        zigbee.state_waiting = true;
        break;
    }
  }
}

#endif // USE_ZIGBEE
