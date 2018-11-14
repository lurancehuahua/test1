#ifndef ZIGBEE_H__
#define ZIGBEE_H__


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <errno.h>
#include "newLog.h"



typedef signed char     int8;
typedef unsigned char   uint8;

typedef signed short    int16;
typedef unsigned short  uint16;

typedef signed int      int32;
typedef unsigned int    uint32;

typedef signed long     int64;
typedef unsigned long   uint64;

typedef uint8           bool;

#define FALSE   0
#define TRUE    1

#define MAX_DEV_NUM 500
#define DEVICE_LIST_MAX (1024*8)
#define SQL_BUF_MAX (1024*8)  /* 8k */

#define SIZE_64B 64
#define SIZE_256B 256
#define SIZE_512B 512

#define SIZE_1K	1024
#define SIZE_2K 2048
#define SIZE_8K 8192
#define SIZE_15K 15360
#define SIZE_16BYTE 16

#define RECEIVE_CLIENT_REQUEST_BUFFER_SIZE SIZE_15K

#define REPORT_BUFF_SIZE (1024*8)
#define OTA_RAM_BUF_SIZE (1024*512)

#define SYSTEM_LOG_FILE_URL "/tmp/logSystem.txt"

void get_systemtime_to_logfile(void);
int get_linux_file_size(const char* filename);

/* open or close debug rs232 transmit data 
*	open next define and open rs232.h RS232_DEBUG
*/
// #define DBG_RS232_DATA


//#define _LOG_FILE(filename,...) fileArgLog(filename,__VA_ARGS__);

#ifndef _LOG_2_FILE
#define _LOG_2_FILE(...) freopen(SYSTEM_LOG_FILE_URL, "a", stdout); \
		get_systemtime_to_logfile();\
		printf(__VA_ARGS__)
#endif

#define DEBUG_2LOGFILE
#ifdef DEBUG_2LOGFILE
#define _DBG(...)   	_LOG_2_FILE(__VA_ARGS__)
#define _DBG_INDEX(...) _LOG_2_FILE("\nIndex--> file:%s func:%s line:%d\n", __FILE__ , __FUNCTION__, __LINE__)
#define ZG_DBG(...)   	_LOG_2_FILE(__VA_ARGS__)
#define ZG_INFO(...)    _LOG_2_FILE(__VA_ARGS__)
#define ZG_DEBUG(...)	_LOG_2_FILE(__VA_ARGS__)
#define ZG_LINE(...)    _LOG_2_FILE("GOTOLINE: %s, %d\n", __FUNCTION__, __LINE__)
#define ZG_ENTER(...)   _LOG_2_FILE("Enter: %s, %d\n", __FUNCTION__, __LINE__)
#define ZG_LEAVE(...)   _LOG_2_FILE("Leave: %s, %d\n", __FUNCTION__, __LINE__)

#define SQL_ERR(...)  	_LOG_2_FILE(__VA_ARGS__)
#define SQL_DBG(...)  	_LOG_2_FILE(__VA_ARGS__)
#define SQL_DEBUG(...)	_LOG_2_FILE(__VA_ARGS__)
#define SQL_INFO(...)	_LOG_2_FILE(__VA_ARGS__)

#else
#define _DBG(...)   	printf(__VA_ARGS__)
#define _DBG_INDEX(...) printf("\nIndex--> file:%s func:%s line:%d\n", __FILE__ , __FUNCTION__, __LINE__)
#define ZG_DBG(...)   	printf(__VA_ARGS__)
#define ZG_INFO(...)    printf(__VA_ARGS__)
#define ZG_DEBUG(...)	printf(__VA_ARGS__)
#define ZG_LINE(...)    ZG_INFO("GOTOLINE: %s, %d\n", __FUNCTION__, __LINE__)
#define ZG_ENTER(...)   ZG_DBG("Enter: %s, %d\n", __FUNCTION__, __LINE__)
#define ZG_LEAVE(...)   ZG_DBG("Leave: %s, %d\n", __FUNCTION__, __LINE__)

#define SQL_ERR(...)	printf(__VA_ARGS__)
#define SQL_DBG(...)	printf(__VA_ARGS__)
#define SQL_DEBUG(...)	printf(__VA_ARGS__)
#define SQL_INFO(...)	printf(__VA_ARGS__)

#endif

#define CHECKOUT_PARA_NULL(para) (para == NULL) ? "" : para
#define CHECKOUT_REPORT_DATE(para) (para == NULL) ? "-1" : para
#define CHECKOUT_GREATER_THAN_ZERO(para) (para > 0) ? (para) : (0)
#define REPLACE_GREATER_THAN_ZERO(para,replaceNum) (para > 0) ? (para) : (replaceNum)


#define ONOFF_CLUSTER_ID  (0x0006)
#define ONOFF_ATTRIBUTE_ID  (0x0000)

#define LEVEL_CONTROL_CLUSTER_ID  (0x0008)
#define CURRENT_LEVEL_ATTRIBUTE_ID  (0x0000)

#define COLOR_CONTROL_CLUSTER_ID  (0x0300)
#define CURRENT_HUE_ATTRIBUTE_ID  (0x0000)
#define COLOR_TEMPERATURE_MIREDS_ATTRIBUTE_ID  (0x0007)

#define ELECTRICAL_MEASUREMENT_CLUSTER_ID  (0x0B04)
#define ACTIVE_POWER_ATTRIBUTE_ID  (0x050B)
#define MAN_SPEC_DIVISOR_ATTRIBUTE_ID (0xFF08)

#define E_SL_MSG_READ_ATTRIBUTE_REQUEST_PLUG_RATED_POWER (0x9001)
#define E_SL_MSG_WRITE_ATRIBUTE_SET_PLUG_ALARM_VALUE (0x9002)
#define E_SL_MSG_READ_PLUG_SET_RATED_VALUE (0x9003)
#define E_SL_MSG_READ_ENDDEVICE_CURRENT_VERSION (0x9004)
#define E_SL_MSG_CONFIG_ALL_PARAMETER (0x9005)
#define PLUG_REAED_WATT_ATTRIBUTE_ID (0x0803)
#define PLUG_ALARM_WATT_ATTRIBUTE_ID (0xFF00)

#define METERING_CLUSTER_ID (0x0702)
#define CURRENT_SUMMATION_ATTRIBUTE_ID (0x0000)
#define INSTANTANEOUSD_DEMAND_ATTRIBUTE_ID (0x0400)

#define GROUP_TASK_ID (64)

#define READ_REG(baseAddr,offset)			(*((uint32 *)((char *)baseAddr + offset)))
#define WRITE_REG(baseAddr,offset,value)	(*((uint32 *)((char *)baseAddr + offset)) = (value))

#if 1
#define SET_SPIMISO_TO_GPIO(value) 			(value | (1 << 4))
#define SET_RESET_TO_GPIO(value)		    (value | (1 << 6))
#define SET_SPIMISO_OUTPUT_DIRECTION(value) (value | (1 << 10))
#define SET_RESET_OUTPUT_DIRECTION(value)   (value | (1 << 9))
#define SET_SPIMISO_HIGH_VALUE(value)       (value | (1 << 10))
#define SET_RESET_HIGH_VALUE(value) 	    (value | (1 << 9))
#define SET_SPIMISO_LOW_VALUE(value)		(value & (~(1 << 10)))
#define SET_RESET_LOW_VALUE(value)			(value & (~(1 << 9)))
#endif

typedef enum
{
	MT7688_GPIO_MODE 					= (0x64)  ,
	MT7688_GPIO_DIRECTION				= (0x604) ,
	MT7688_GPIO_VALUE					= (0x624) 
} teMT7688Mode;

typedef enum
{
	READ_REG_OPERATION	,		
	WRITE_REG_OPERATION					
} teRegOperation;

typedef enum
{
	MT7688_UPDATE_JN5169_START           = 1,
	MT7688_UPDATE_JN5169_UPDATING        = 2,
	MT7688_UPDATE_JN5169_SUCCESSFUL      = 3,
	MT7688_UPDATE_JN5169_ERROR           = 4
} teMT7688UpdateJN5169;

typedef enum
{
/* Common Commands */
    E_SL_MSG_STATUS                                            =   0x8000,
    E_SL_MSG_LOG                                               =   0x8001,

    E_SL_MSG_DATA_INDICATION                                   =   0x8002,

    E_SL_MSG_NODE_CLUSTER_LIST                                 =   0x8003,
    E_SL_MSG_NODE_ATTRIBUTE_LIST                               =   0x8004,
    E_SL_MSG_NODE_COMMAND_ID_LIST                              =   0x8005,
    E_SL_MSG_NODE_NON_FACTORY_NEW_RESTART                      =   0x8006,
    E_SL_MSG_NODE_FACTORY_NEW_RESTART                          =   0x8007,
    E_SL_MSG_GET_VERSION                                       =   0x0010,
    E_SL_MSG_VERSION_LIST                                      =   0x8010,

    E_SL_MSG_SET_EXT_PANID                                     =   0x0020,
    E_SL_MSG_SET_CHANNELMASK                                   =   0x0021,
    E_SL_MSG_SET_SECURITY                                      =   0x0022,
    E_SL_MSG_SET_DEVICETYPE                                    =   0x0023,
    E_SL_MSG_START_NETWORK                                     =   0x0024,
    E_SL_MSG_START_SCAN                                        =   0x0025,
    E_SL_MSG_NETWORK_JOINED_FORMED                             =   0x8024,
    E_SL_MSG_NETWORK_REMOVE_DEVICE                             =   0x0026,
    E_SL_MSG_NETWORK_WHITELIST_ENABLE                          =   0x0027,
    E_SL_MSG_ADD_AUTHENTICATE_DEVICE                           =   0x0028,
    E_SL_MSG_UPDATE_AUTHENTICATE_DEVICE                        =   0x002A,
    E_SL_MSG_AUTHENTICATE_DEVICE_RESPONSE                      =   0x8028,

    E_SL_MSG_RESET                                             =   0x0011,
    E_SL_MSG_ERASE_PERSISTENT_DATA                             =   0x0012,
    E_SL_MSG_ZLL_FACTORY_NEW                                   =   0x0013,
    E_SL_MSG_GET_PERMIT_JOIN                                   =   0x0014,
    E_SL_MSG_GET_PERMIT_JOIN_RESPONSE                          =   0x8014,
    E_SL_MSG_BIND                                              =   0x0030,
    E_SL_MSG_BIND_RESPONSE                                     =   0x8030,
    E_SL_MSG_UNBIND                                            =   0x0031,
    E_SL_MSG_UNBIND_RESPONSE                                   =   0x8031,
    E_SL_MSG_BIND_GROUP                                        =   0x0032,
    E_SL_MSG_BIND_GROUP_RESPONSE                               =   0x8032,
    E_SL_MSG_UNBIND_GROUP                                      =   0x0033,
    E_SL_MSG_UNBIND_GROUP_RESPONSE                             =   0x8033,

    E_SL_MSG_MANY_TO_ONE_ROUTE_REQUEST                         =   0x004F,
    E_SL_MSG_COMPLEX_DESCRIPTOR_REQUEST                        =   0x0034,
    E_SL_MSG_COMPLEX_DESCRIPTOR_RESPONSE                       =   0x8034,
    E_SL_MSG_NETWORK_ADDRESS_REQUEST                           =   0x0040,
    E_SL_MSG_NETWORK_ADDRESS_RESPONSE                          =   0x8040,
    E_SL_MSG_IEEE_ADDRESS_REQUEST                              =   0x0041,
    E_SL_MSG_IEEE_ADDRESS_RESPONSE                             =   0x8041,
    E_SL_MSG_NODE_DESCRIPTOR_REQUEST                           =   0x0042,
    E_SL_MSG_NODE_DESCRIPTOR_RESPONSE                          =   0x8042,
    E_SL_MSG_SIMPLE_DESCRIPTOR_REQUEST                         =   0x0043,
    E_SL_MSG_SIMPLE_DESCRIPTOR_RESPONSE                        =   0x8043,
    E_SL_MSG_POWER_DESCRIPTOR_REQUEST                          =   0x0044,
    E_SL_MSG_POWER_DESCRIPTOR_RESPONSE                         =   0x8044,
    E_SL_MSG_ACTIVE_ENDPOINT_REQUEST                           =   0x0045,
    E_SL_MSG_ACTIVE_ENDPOINT_RESPONSE                          =   0x8045,
    E_SL_MSG_MATCH_DESCRIPTOR_REQUEST                          =   0x0046,
    E_SL_MSG_MATCH_DESCRIPTOR_RESPONSE                         =   0x8046,
    E_SL_MSG_MANAGEMENT_LEAVE_REQUEST                          =   0x0047,
    E_SL_MSG_MANAGEMENT_LEAVE_RESPONSE                         =   0x8047,
    E_SL_MSG_LEAVE_INDICATION                                  =   0x8048,
    E_SL_MSG_PERMIT_JOINING_REQUEST                            =   0x0049,
    E_SL_MSG_PERMIT_JOINING_RESPONSE                           =   0x8049,
    E_SL_MSG_MANAGEMENT_NETWORK_UPDATE_REQUEST                 =   0x004A,
    E_SL_MSG_MANAGEMENT_NETWORK_UPDATE_RESPONSE                =   0x804A,
    E_SL_MSG_SYSTEM_SERVER_DISCOVERY                           =   0x004B,
    E_SL_MSG_SYSTEM_SERVER_DISCOVERY_RESPONSE                  =   0x804B,
    E_SL_MSG_LEAVE_REQUEST                                     =   0x004C,
    E_SL_MSG_DEVICE_ANNOUNCE                                   =   0x004D,
    E_SL_MSG_MANAGEMENT_LQI_REQUEST                            =   0x004E,
    E_SL_MSG_MANAGEMENT_LQI_RESPONSE                           =   0x804E,
    E_SL_MSG_USER_DESC_SET                                     =   0x002B,
    E_SL_MSG_USER_DESC_REQ                                     =   0x002C,
    E_SL_MSG_USER_DESC_NOTIFY                                  =   0x802B,
    E_SL_MSG_USER_DESC_RSP                                     =   0x802C,


    /* Basic Cluster */
    E_SL_MSG_BASIC_RESET_TO_FACTORY_DEFAULTS                   =   0x0050,
    E_SL_MSG_BASIC_RESET_TO_FACTORY_DEFAULTS_RESPONSE          =   0x8050,

    /* Group Cluster */
    E_SL_MSG_ADD_GROUP                                         =   0x0060,
    E_SL_MSG_ADD_GROUP_RESPONSE                                =   0x8060,
    E_SL_MSG_VIEW_GROUP                                        =   0x0061,
    E_SL_MSG_VIEW_GROUP_RESPONSE                               =   0x8061,
    E_SL_MSG_GET_GROUP_MEMBERSHIP                              =   0x0062,
    E_SL_MSG_GET_GROUP_MEMBERSHIP_RESPONSE                     =   0x8062,
    E_SL_MSG_REMOVE_GROUP                                      =   0x0063,
    E_SL_MSG_REMOVE_GROUP_RESPONSE                             =   0x8063,
    E_SL_MSG_REMOVE_ALL_GROUPS                                 =   0x0064,
    E_SL_MSG_ADD_GROUP_IF_IDENTIFY                             =   0x0065,

    /* Identify Cluster */
    E_SL_MSG_IDENTIFY_SEND                                     =   0x0070,
    E_SL_MSG_IDENTIFY_QUERY                                    =   0x0071,
    E_SL_MSG_IDENTIFY_LOCAL_ACTIVE                             =   0x807a,

    /* Level Cluster */
    E_SL_MSG_MOVE_TO_LEVEL                                     =   0x0080,
    E_SL_MSG_MOVE_TO_LEVEL_ONOFF                               =   0x0081,
    E_SL_MSG_MOVE_STEP                                         =   0x0082,
    E_SL_MSG_MOVE_STOP_MOVE                                    =   0x0083,
    E_SL_MSG_MOVE_STOP_ONOFF                                   =   0x0084,

    /* Scenes Cluster */
    E_SL_MSG_VIEW_SCENE                                        =   0x00A0,
    E_SL_MSG_VIEW_SCENE_RESPONSE                               =   0x80A0,
    E_SL_MSG_ADD_SCENE                                         =   0x00A1,
    E_SL_MSG_ADD_SCENE_RESPONSE                                =   0x80A1,
    E_SL_MSG_REMOVE_SCENE                                      =   0x00A2,
    E_SL_MSG_REMOVE_SCENE_RESPONSE                             =   0x80A2,
    E_SL_MSG_REMOVE_ALL_SCENES                                 =   0x00A3,
    E_SL_MSG_REMOVE_ALL_SCENES_RESPONSE                        =   0x80A3,
    E_SL_MSG_STORE_SCENE                                       =   0x00A4,
    E_SL_MSG_STORE_SCENE_RESPONSE                              =   0x80A4,
    E_SL_MSG_RECALL_SCENE                                      =   0x00A5,
    E_SL_MSG_SCENE_MEMBERSHIP_REQUEST                          =   0x00A6,
    E_SL_MSG_SCENE_MEMBERSHIP_RESPONSE                         =   0x80A6,

    /* Colour Cluster */
    E_SL_MSG_MOVE_TO_HUE                                       =   0x00B0,
    E_SL_MSG_MOVE_HUE                                          =   0x00B1,
    E_SL_MSG_STEP_HUE                                          =   0x00B2,
    E_SL_MSG_MOVE_TO_SATURATION                                =   0x00B3,
    E_SL_MSG_MOVE_SATURATION                                   =   0x00B4,
    E_SL_MSG_STEP_SATURATION                                   =   0x00B5,
    E_SL_MSG_MOVE_TO_HUE_SATURATION                            =   0x00B6,
    E_SL_MSG_MOVE_TO_COLOUR                                    =   0x00B7,
    E_SL_MSG_MOVE_COLOUR                                       =   0x00B8,
    E_SL_MSG_STEP_COLOUR                                       =   0x00B9,

    /* ZLL Commands */
    /* Touchlink */
    E_SL_MSG_INITIATE_TOUCHLINK                                =   0x00D0,
    E_SL_MSG_TOUCHLINK_STATUS                                  =   0x00D1,
    E_SL_MSG_TOUCHLINK_FACTORY_RESET                           =   0x00D2,
    /* Identify Cluster */
    E_SL_MSG_IDENTIFY_TRIGGER_EFFECT                           =   0x00E0,

    /* On/Off Cluster */
    E_SL_MSG_ONOFF_NOEFFECTS                                   =   0x0092,
    E_SL_MSG_ONOFF_TIMED                                       =   0x0093,
    E_SL_MSG_ONOFF_EFFECTS                                     =   0x0094,
    E_SL_MSG_ONOFF_UPDATE                                      =   0x8095,

    /* Scenes Cluster */
    E_SL_MSG_ADD_ENHANCED_SCENE                                =   0x00A7,
    E_SL_MSG_VIEW_ENHANCED_SCENE                               =   0x00A8,
    E_SL_MSG_COPY_SCENE                                        =   0x00A9,

    /* Colour Cluster */
    E_SL_MSG_ENHANCED_MOVE_TO_HUE                              =   0x00BA,
    E_SL_MSG_ENHANCED_MOVE_HUE                                 =   0x00BB,
    E_SL_MSG_ENHANCED_STEP_HUE                                 =   0x00BC,
    E_SL_MSG_ENHANCED_MOVE_TO_HUE_SATURATION                   =   0x00BD,
    E_SL_MSG_COLOUR_LOOP_SET                                   =   0x00BE,
    E_SL_MSG_STOP_MOVE_STEP                                    =   0x00BF,
    E_SL_MSG_MOVE_TO_COLOUR_TEMPERATURE                        =   0x00C0,
    E_SL_MSG_MOVE_COLOUR_TEMPERATURE                           =   0x00C1,
    E_SL_MSG_STEP_COLOUR_TEMPERATURE                           =   0x00C2,

    /* Door Lock Cluster */
    E_SL_MSG_LOCK_UNLOCK_DOOR                                  =   0x00F0,

    /* ZHA Commands */
    E_SL_MSG_READ_ATTRIBUTE_REQUEST                             =  0x0100,
    E_SL_MSG_READ_ATTRIBUTE_RESPONSE                            =  0x8100,
    E_SL_MSG_DEFAULT_RESPONSE                                   =  0x8101,
    E_SL_MSG_REPORT_IND_ATTR_RESPONSE                           =  0x8102,
    E_SL_MSG_WRITE_ATTRIBUTE_REQUEST                            =  0x0110,
    E_SL_MSG_WRITE_ATTRIBUTE_RESPONSE                           =  0x8110,
    E_SL_MSG_CONFIG_REPORTING_REQUEST                           =  0x0120,
    E_SL_MSG_CONFIG_REPORTING_RESPONSE                          =  0x8120,
    E_SL_MSG_REPORT_ATTRIBUTES                                  =  0x8121,
    E_SL_MSG_READ_REPORT_CONFIG_REQUEST                         =  0x0122,
    E_SL_MSG_READ_REPORT_CONFIG_RESPONSE                        =  0x8122,
    E_SL_MSG_ATTRIBUTE_DISCOVERY_REQUEST                        =  0x0140,
    E_SL_MSG_ATTRIBUTE_DISCOVERY_RESPONSE                       =  0x8140,
    E_SL_MSG_ATTRIBUTE_EXT_DISCOVERY_REQUEST                    =  0x0141,
    E_SL_MSG_ATTRIBUTE_EXT_DISCOVERY_RESPONSE                   =  0x8141,
    E_SL_MSG_COMMAND_RECEIVED_DISCOVERY_REQUEST                 =  0x0150,
    E_SL_MSG_COMMAND_RECEIVED_DISCOVERY_INDIVIDUAL_RESPONSE     =  0x8150,
    E_SL_MSG_COMMAND_RECEIVED_DISCOVERY_RESPONSE                =  0x8151,
    E_SL_MSG_COMMAND_GENERATED_DISCOVERY_REQUEST                =  0x0160,
    E_SL_MSG_COMMAND_GENERATED_DISCOVERY_INDIVIDUAL_RESPONSE    =  0x8160,
    E_SL_MSG_COMMAND_GENERATED_DISCOVERY_RESPONSE               =  0x8161,

    E_SL_MSG_SAVE_PDM_RECORD                                    =  0x0200,
    E_SL_MSG_SAVE_PDM_RECORD_RESPONSE                           =  0x8200,
    E_SL_MSG_LOAD_PDM_RECORD_REQUEST                            =  0x0201,
    E_SL_MSG_LOAD_PDM_RECORD_RESPONSE                           =  0x8201,
    E_SL_MSG_DELETE_PDM_RECORD                                  =  0x0202,

    E_SL_MSG_PDM_HOST_AVAILABLE                                 =  0x0300,
    E_SL_MSG_ASC_LOG_MSG                                        =  0x0301,
    E_SL_MSG_ASC_LOG_MSG_RESPONSE                               =  0x8301,
    E_SL_MSG_PDM_HOST_AVAILABLE_RESPONSE                        =  0x8300,
    /* IAS Cluster */
    E_SL_MSG_SEND_IAS_ZONE_ENROLL_RSP                           =  0x0400,
    E_SL_MSG_IAS_ZONE_STATUS_CHANGE_NOTIFY                      =  0x8401,

    /* OTA Cluster */
    E_SL_MSG_LOAD_NEW_IMAGE                                     =  0x0500,
    E_SL_MSG_NEXT_IMAGE_REQUEST									=  0x8502,				
    E_SL_MSG_BLOCK_REQUEST                                      =  0x8501,
    E_SL_MSG_BLOCK_SEND                                         =  0x0502,
    E_SL_MSG_UPGRADE_END_REQUEST                                =  0x8503,
    E_SL_MSG_UPGRADE_END_RESPONSE                               =  0x0504,
    E_SL_MSG_IMAGE_NOTIFY                                       =  0x0505,
    E_SL_MSG_SEND_WAIT_FOR_DATA_PARAMS                          =  0x0506,
    E_SL_MSG_SEND_RAW_APS_DATA_PACKET                          =   0x0530,

    E_SL_MSG_NWK_RECOVERY_EXTRACT_REQ                           =  0x0600,
    E_SL_MSG_NWK_RECOVERY_EXTRACT_RSP                           =  0x8600,
    E_SL_MSG_NWK_RECOVERY_RESTORE_REQ                           =  0x0601,
    E_SL_MSG_NWK_RECOVERY_RESTORE_RSP                           =  0x8601,

    E_SL_MSG_ROUTE_DISCOVERY_CONFIRM                            =  0x8701,
    E_SL_MSG_APS_DATA_CONFIRM_FAILED                            =  0x8702,

    E_SL_MSG_INIT_DEVICE_REQ                                     =  0x0A01,
    E_SL_MSG_MEASUREMENT_ELECTRIC_USE_HOUR_REQ                   =  0x0A05,
    E_SL_MSG_MEASUREMENT_ELECTRIC_USE_HOUR_RSP                   =  0x8A05,
    E_SL_MSG_MEASUREMENT_ELECTRIC_USE_ENERGE_REQ                 =  0x0A06,
    E_SL_MSG_MEASUREMENT_ELECTRIC_USE_ENERGE_RSP                 =  0x8A06,
} teMsgType;

typedef enum
{
    E_ZCL_AM_BOUND,
    E_ZCL_AM_GROUP,
    E_ZCL_AM_SHORT,
    E_ZCL_AM_IEEE,
    E_ZCL_AM_BROADCAST,
    E_ZCL_AM_NO_TRANSMIT,
    E_ZCL_AM_BOUND_NO_ACK,
    E_ZCL_AM_SHORT_NO_ACK,
    E_ZCL_AM_IEEE_NO_ACK,
    E_ZCL_AM_BOUND_NON_BLOCKING,
    E_ZCL_AM_BOUND_NON_BLOCKING_NO_ACK,
    E_ZCL_AM_ENUM_END /* enum End */
} teZCL_AddressMode;


typedef enum
{
    E_ZHA_ONF_SWITCH_PROFILE_ID = 0x0000, 
    E_ZHA_LEVEL_CONTROL_SWITCH_PROFILE_ID = 0x0001,
    E_ZHA_ONF_OUTPUT_PROFILE_ID = 0x0002,
    E_ZHA_LEVEL_CONTROL_OUTPUT_PROFILE_ID = 0x0003,
    E_ZHA_SCENE_SELECTOR_PROFILE_ID = 0x0004,
    E_ZHA_CONFIGURATION_TOOL_PROFILE_ID = 0x0005,
    E_ZHA_REMOTE_CONTROL_PROFILE_ID = 0x0006,
    E_ZHA_COMBINED_INTERFACE_PROFILE_ID = 0x0007,
    E_ZHA_RANGE_EXTENDER_PROFILE_ID = 0x0008,
    E_ZHA_MAINS_POWER_OUTLET_PROFILE_ID = 0x0009,
    E_ZHA_DOOR_LOCK_PROFILE_ID = 0x000A,
    E_ZHA_DOOR_LOCK_CONTROLLER_PROFILE_ID = 0x000B,
    E_ZHA_SIMPLE_SENSOR_PROFILE_ID = 0x000C,
    E_ZHA_CONSUMPTION_AWARENESS_PROFILE_ID = 0x000D,

    E_ZHA_ONF_PLUG_PROFILE_ID = 0x0010,

    E_ZHA_HOME_GATEWAY_PROFILE_ID = 0x0050,
    E_ZHA_SMART_PLUG_PROFILE_ID = 0x0051,
    E_ZHA_WHITE_GOODS_PROFILE_ID = 0x0052,
    E_ZHA_METER_INTERFACE_PROFILE_ID = 0x0053,
    
    E_ZHA_ONF_LIGHT_PROFILE_ID = 0x0100,
    E_ZHA_DIMMABLE_LIGHT_PROFILE_ID = 0x0101,
    E_ZHA_COLOR_DIMMABLE_LIGHT_PROFILE_ID = 0x0102,
    E_ZHA_ONF_LIGHT_SWITCH_PROFILE_ID = 0x0103,
    E_ZHA_DIMMER_SWITCH_PROFILE_ID = 0x0104,
    E_ZHA_COLOR_DIMMER_SWITCH_PROFILE_ID = 0x0105,
    E_ZHA_LIGHT_SENSOR_PROFILE_ID = 0x0106,
    E_ZHA_OCCUPANCY_SENSOR_PROFILE_ID = 0x0107,

    E_Z30_ONF_BALLAST_PROFILE_ID = 0x0108,
    E_Z30_DIMMABLE_BALLAST_PROFILE_ID = 0x0109,
    E_Z30_ONF_PLUGIN_PROFILE_ID = 0x010A,
    E_Z30_DIMMABLE_PLUGIN_PROFILE_ID = 0x010B,
    E_Z30_COLOR_TEMPERATURE_LIGHT_PROFILE_ID = 0x010C,
    E_Z30_EXTENDED_COLOR_LIGHT_PROFILE_ID = 0x010D,
    E_Z30_LIGHT_LEVEL_SENSOR_PROFILE_ID = 0x010E,

/* ZLL 0x0000, 0x0001, 0x0100 is differ to ZHA
        E_ZLL_ONF_LIGHT_PROFILE_ID = 0x0000,
        E_ZLL_ONF_PLUGIN_PROFILE_ID = 0x0001,
        E_ZLL_DIMMABLE_LIGHT_PROFILE_ID = 0x0100,
*/
    E_ZLL_DIMMABLE_PLUGIN_PROFILE_ID = 0x0110,
    E_ZLL_COLOR_LIGHT_PROFILE_ID = 0x0200,
    E_ZLL_EXTENDED_COLOR_LIGHT_PROFILE_ID = 0x0210,
    E_ZLL_COLOR_TEMPERATURE_LIGHT_PROFILE_ID = 0x0220,
    
    E_ZLL_COLOR_CONTROLLER_PROFILE_ID = 0x0800,
    E_ZLL_COLOR_SCENE_CONTROLLER_PROFILE_ID = 0x0810,
    E_ZLL_NONCOLOR_CONTROLLER_PROFILE_ID = 0x0820,
    E_ZLL_NONCOLOR_SCENE_CONTROLLER_PROFILE_ID = 0x0830,
    E_ZLL_CONTROL_BRIDGE_PROFILE_ID = 0x0840,
    E_ZLL_ONF_SENSOR_PROFILE_ID = 0x0850,
    
    E_ZLL_ONF_LIGHT_PROFILE_ID = 0x0900,
    E_ZLL_ONF_PLUGIN_PROFILE_ID = 0x0901,
    E_ZLL_DIMMABLE_LIGHT_PROFILE_ID = 0x0902,
}teDeviceProfileId;


typedef enum
{
    E_MSG_EVENT_START,
    E_MSG_EVENT_NOT_FIND,
    E_MSG_EVENT_FINISH,
    E_MSG_EVENT_ERROR,
}teMsgEventStatus;


typedef struct
{
    teDeviceProfileId teDeviceId;
    unsigned short tag;
    char name[128];
}tsDeviceWebdef;

typedef enum
{
	T_CTL_ADD						= 1,
	T_CTL_UPDATE					= 2,
	T_CTL_DELETE					= 3,
	T_CTL_GET_LQI_STATUS 			= 4,   // get all device lqi
	T_CTL_GET_ONE_DEVICE_LQI_STATUS = 5,   // get device list lqi
	T_CTL_SELF_RECOVERY_ADD_GROUP   = 6,
	T_CTL_CHECK_DEVICE_GROUP_STATUS = 7,
	T_CLT_SET_PLUG_ALARM_VALUE		= 8,	/* SET ALL PLUG ALARM  */
	T_CTL_GET_DEVICE_CURRENT_VERSION = 9
} taskControlMethod;

typedef enum
{
	T_HANDLER_NOT_START		= 1,
	T_HANDLER_STARTING		= 2,
	T_HANDLER_SUCCESSFUL	= 3,
	T_HANDLER_ERROR			= 4
} taskHandlerStatus;

typedef enum
{
    E_INIT_WAIT,
    E_INIT_START,
    E_INIT_ACTIVE_ENDPOINT_REQ,
    E_INIT_SIMPLE_DESCRIPTOR_REQ,
    E_INIT_NODE_DESCRIPTOR_REQ,
    E_INIT_BASIC_CLUSTER_REQ_STEP_1,
    E_INIT_BASIC_CLUSTER_REQ_STEP_2,
    E_INIT_GROUP_MEMBERSHIP_REQ,
    E_INIT_ONOFF_REPORT_CONFIG_REQ,
    E_INIT_ONOFF_BIND_REQ,
    E_INIT_LEVEL_REPORT_CONFIG_REQ,
    E_INIT_LEVEL_BIND_REQ,
    E_INIT_COLOR_REPORT_CONFIG_REQ,
    E_INIT_COLOR_TEMPERATURE_REPORT_CONFIG_REQ,
    E_INIT_COLOR_BIND_REQ,
    E_INIT_METERING_REPORT_CONFIG_REQ,
    E_INIT_METERING_BIND_REQ,
    E_INIT_ELECTRICAL_MEASUREMENT_REPORT_CONFIG_REQ,
    E_INIT_ELECTRICAL_MEASUREMENT_BIND_REQ,
    E_INIT_FINISH,
} teInitDeviceStatus;


typedef struct
{
	uint16 groupId;
	char*  p_taskId;
	char*  p_deviceList;
	char*  p_successDeviceList;
	char*  p_successDeleteDeviceList;
	char*  p_errDeviceList;
	taskControlMethod controlMethod;
	taskHandlerStatus taskStatus;
}dbGroupTaskParameter;

typedef struct stResportMsg
{
	char searchTimeTitleName[SIZE_16BYTE];
	char searchSwitchTitleName[SIZE_16BYTE];
	char serverIp[SIZE_16BYTE];
	uint16 serverPort;
	uint32 rpTime;
	uint32 rpSwitch;
}resportMsg;

#define ZNC_BUF_U8_UPD( BUFFER, U8VALUE, LEN)    (  ( *( (uint8*)( ( BUFFER ) ) ) = ( ( ( ( uint8 ) ( U8VALUE ) ) & 0xFF ) ) ) ,\
     ( ( LEN ) += sizeof( uint8 ) ) )

#define ZNC_BUF_U16_UPD( BUFFER, U16VALUE, LEN )     ( ( *( uint8* )( BUFFER )   =  ( uint8 )  ( ( ( ( uint16)( U16VALUE ) ) >> 8 ) & 0xFF ) ),\
    ( *( uint8* ) ( ( BUFFER ) + 1 )  =  ( uint8 )  ( ( ( ( uint16 )( U16VALUE ) ) ) & 0xFF ) ) ,\
    ( ( LEN ) += sizeof( uint16 ) ) )

#define ZNC_BUF_U32_UPD( BUFFER, U32VALUE, LEN )     ( ( *( uint8* )( BUFFER )   =  ( uint8 ) ( ( ( ( uint32 ) ( U32VALUE ) ) >> 24 ) & 0xFF ) ),\
    ( *( uint8* )( ( BUFFER ) + 1) =  ( uint8 ) ( ( ( ( uint32 ) ( U32VALUE ) ) >> 16 ) & 0xFF ) ),\
    ( *( uint8* )( ( BUFFER ) + 2) =  ( uint8 ) ( ( ( ( uint32 ) ( U32VALUE ) ) >> 8 ) & 0xFF ) ),\
    ( *( uint8* )( ( BUFFER ) + 3) =  ( uint8 ) ( ( ( ( uint32 ) ( U32VALUE ) ) & 0xFF ) ) ) ,\
    ( ( LEN ) += sizeof ( uint32 ) ) )

#define ZNC_BUF_U64_UPD( BUFFER, U64VALUE, LEN)    ( ( *(uint8*) ( BUFFER ) = (uint8) ( ( ( ( uint64 ) ( U64VALUE ) ) >> 56) & 0xFF)),\
    ( *(uint8*) ( ( BUFFER ) + 1) = (uint8) ( ( ( ( uint64 ) ( U64VALUE ) ) >> 48) & 0xFF ) ),\
    ( *(uint8*) ( ( BUFFER ) + 2) = (uint8) ( ( ( ( uint64 ) ( U64VALUE ) ) >> 40) & 0xFF ) ),\
    ( *(uint8*) ( ( BUFFER ) + 3) = (uint8) ( ( ( ( uint64 ) ( U64VALUE ) ) >> 32) & 0xFF ) ),\
    ( *(uint8*) ( ( BUFFER ) + 4) = (uint8) ( ( ( ( uint64 ) ( U64VALUE ) ) >> 24) & 0xFF ) ),\
    ( *(uint8*) ( ( BUFFER ) + 5) = (uint8) ( ( ( ( uint64 ) ( U64VALUE ) ) >> 16) & 0xFF ) ),\
    ( *(uint8*) ( ( BUFFER ) + 6) = (uint8) ( ( ( ( uint64 ) ( U64VALUE ) ) >>  8) & 0xFF ) ),\
    ( *(uint8*) ( ( BUFFER ) + 7) = (uint8) ( ( ( ( uint64 ) ( U64VALUE ) ) & 0xFF ) ) ),\
    ( ( LEN ) += sizeof( uint64 ) ) )

/* Macros take the buffer pointer and return the data */
#define ZNC_RTN_U8( BUFFER, i )  (( ( uint8 ) (BUFFER)[ i ] & 0xFF))

#define ZNC_RTN_U16( BUFFER, i ) ( ( ( uint16 ) (BUFFER)[ i ] << 8) |\
    ( ( uint16 ) (BUFFER)[ i + 1 ] & 0xFF))\
    
#define ZNC_RTN_U32( BUFFER, i ) ( ( ( uint32 ) ( BUFFER )[ i ] << 24) |\
        ( ( uint32 ) ( BUFFER )[ i + 1 ]  << 16) |\
        ( ( uint32 ) ( BUFFER )[ i + 2 ]  << 8) |\
        ( ( uint32 ) ( BUFFER )[ i + 3 ] & 0xFF))\

#define ZNC_RTN_U64( BUFFER, i )  ( ( ( uint64 ) ( BUFFER )[ i ]  <<  56) |\
    ( ( uint64 ) ( BUFFER )[ i + 1 ]  << 48) |\
    ( ( uint64 ) ( BUFFER )[ i + 2 ]  << 40) |\
    ( ( uint64 ) ( BUFFER )[ i + 3 ]  << 32) |\
    ( ( uint64 ) ( BUFFER )[ i + 4 ]  << 24) |\
    ( ( uint64 ) ( BUFFER )[ i + 5 ]  << 16) |\
    ( ( uint64 ) ( BUFFER )[ i + 6 ]  << 8) |\
    ( ( uint64 ) ( BUFFER )[ i + 7 ] & 0xFF))\

/* Macros take buffer and return data and the next offset of within the buffer */
#define ZNC_RTN_U8_OFFSET(BUFFER, i, OFFSET )   ( ZNC_RTN_U8 (BUFFER, i) );\
( ( OFFSET ) += sizeof (uint8) )

#define ZNC_RTN_U16_OFFSET(BUFFER, i, OFFSET )   ( ZNC_RTN_U16 (BUFFER, i) );\
( ( OFFSET ) += sizeof (uint16) )

#define ZNC_RTN_U32_OFFSET(BUFFER, i, OFFSET )   (  ZNC_RTN_U32 (BUFFER, i) );\
( ( OFFSET ) += sizeof (uint32) )

#define ZNC_RTN_U64_OFFSET(BUFFER, i, OFFSET )  (  ZNC_RTN_U64 (BUFFER, i) );\
( ( OFFSET ) += sizeof (uint64) )





/* little end type, index high is interget high wei. */
#define LN_RTN_U8( BUFFER, i )  (( ( uint8 ) (BUFFER)[ i ] & 0xFF))

#define LN_RTN_U16( BUFFER, i ) ( ( ( uint16 ) (BUFFER)[ i + 1 ] << 8) |\
    ( ( uint16 ) (BUFFER)[ i ] & 0xFF))\
    
#define LN_RTN_U32( BUFFER, i ) ( ( ( uint32 ) ( BUFFER )[ i + 3 ] << 24) |\
        ( ( uint32 ) ( BUFFER )[ i + 2 ]  << 16) |\
        ( ( uint32 ) ( BUFFER )[ i + 1 ]  << 8) |\
        ( ( uint32 ) ( BUFFER )[ i ] & 0xFF))\

#define LN_RTN_U64( BUFFER, i )  ( ( ( uint64 ) ( BUFFER )[ i + 7 ]  <<  56) |\
    ( ( uint64 ) ( BUFFER )[ i + 6 ]  << 48) |\
    ( ( uint64 ) ( BUFFER )[ i + 5 ]  << 40) |\
    ( ( uint64 ) ( BUFFER )[ i + 4 ]  << 32) |\
    ( ( uint64 ) ( BUFFER )[ i + 3 ]  << 24) |\
    ( ( uint64 ) ( BUFFER )[ i + 2 ]  << 16) |\
    ( ( uint64 ) ( BUFFER )[ i + 1 ]  << 8) |\
    ( ( uint64 ) ( BUFFER )[ i ] & 0xFF))\

/* Little end: Macros take buffer and return data and the next offset of within the buffer */
#define LN_RTN_U8_OFFSET(BUFFER, i, OFFSET )   ( LN_RTN_U8 (BUFFER, i) );\
( ( OFFSET ) += sizeof (uint8) )

#define LN_RTN_U16_OFFSET(BUFFER, i, OFFSET )   ( LN_RTN_U16 (BUFFER, i) );\
( ( OFFSET ) += sizeof (uint16) )

#define LN_RTN_U32_OFFSET(BUFFER, i, OFFSET )   (  LN_RTN_U32 (BUFFER, i) );\
( ( OFFSET ) += sizeof (uint32) )

#define LN_RTN_U64_OFFSET(BUFFER, i, OFFSET )  (  LN_RTN_U64 (BUFFER, i) );\
( ( OFFSET ) += sizeof (uint64) )



#define MSG_QUEUE_HOST2NODE_KYE     1234
#define MSG_QUEUE_NODE2HOST_KEY     2345
#define MSG_QUEUE_CMDFALG_KEY       3456

#define QUEUE_MSG_LEN   512

typedef struct
{
    long int msg_type;
    uint16 data_len;
    uint8 data[QUEUE_MSG_LEN];
}tsMsgQueueNode;

typedef struct
{
	uint16 sAddr;
	uint32 mach;
	uint32 macl;
	int onoff;    // not send is -1
	int lum;
	int cct;
	int hue;
	uint8 lqi;
}generalDevicePara;

typedef struct
{
	char cloudServerIP[16];
	uint16 cloudServerPort;
	char gMacId[128];
	uint16 powerTime;
	uint8 powerSwitch;
	uint16 deviceStatusTime;
	uint8 deviceStatusSwitch;
	uint16 addDeviceTime;
	uint8 addDeviceSwitch;
}zgwReportMsg;

typedef struct
{
	char* p_downloadFileAddrList;
	char* p_downloadFileLengthList;
	char* p_hw;
	char* p_md5;
	uint32 u32_version;
	uint8 codeStatus;
}zgwDownloadMsg;

typedef struct
{
	uint32 mt7688Version;
	uint32 jn5169Version;
}gwVersion;

typedef struct
{
	uint32 msgHead;
	uint8 openNetTime;
	char*  p_deviceShortAddrList;
	uint32 groupNum;
	char p_taskId[256];
	uint8 statusValue;
	uint8 sendTimeApart;
	char tk[128];
	uint16 plugAlarmValue;
	zgwReportMsg reportMsg;
	generalDevicePara devPara;
	zgwDownloadMsg downloadMsg;
	gwVersion gatewayVersion;
}httpRequestMsg;

typedef enum
{
	REQUEST_ALL_DEVICE_JSON,   /* MH = 1003 */
	REQUEST_TASK_STATUS,       /* MH = 1015 */
	REQUEST_UPDATE_STATUS
}httpRequestType;

typedef enum
{
	GET_INTEGER,
	GET_STRING
}getDateType;

typedef enum
{
	CTL_SEND_DATA			= 2,
	CTL_SUCCESSFUL			= 3,
	CTL_ERROR				= 4,
	CTL_SEND_TIAL			= 5
}responseFlag;

typedef enum
{
	E_WORK				= 1,
	E_WORK2REST			= 2,
	E_REST2WORK			= 3,
	E_WORKOUT			= 4,
	E_NORMAL			= 5
}emScheduleType;

typedef enum
{
	E_ONOFF			= 1,
	E_LUM			= 2,
	E_CCT			= 3,
	E_RGB			= 4
}emScheduleSendParaType;

typedef struct
{
	emScheduleSendParaType ctlType;
	uint16	onoff;
	uint16	lumStart;
	uint16	lumStop;
	uint16	cctStart;
	uint16	cctStop;
	uint16	hueStart;
	uint16	hueStop;
	uint16	timeUnitInterval;
	int		paraUnitInterval;
}ScheduleHandlerMsg;

typedef enum
{
	RE_SUCCESSFUL		= 1,
	RE_ERROR			= 2,
	RE_EXIST			= 3,
	RE_NOT_EXIST		= 4
}emReturnStatus;

/***        host handler                                             ***/
#define MESSAGE_TRANSMIT_MAX_LENGTH 512

typedef struct
{
    uint16 u16MsgType;
    uint16 u16MsgLen;
    uint8  u8MsgBuf[MESSAGE_TRANSMIT_MAX_LENGTH];
}tsMessageTransmitPackage;

typedef struct 
{
	uint32 powerTime;
	uint8  powerSwitch;
	uint32 addDeviceTime;
	uint8  addDeviceSwitch;
	uint32 deviceChangeTime;
	uint8  deviceChangeStatus;
}stReportTimeandSwitch;

typedef struct tsMsgTxNode
{
    tsMessageTransmitPackage tsMsg;
    struct tsMsgTxNode *next;
}tsMsgTxPackage, *ptsMsgTxNode;

typedef struct
{
	uint32	plugAbnormalReportTime;		/* unit seconds */
	uint32	plugReportLimitValue;		/* uint watt */
	uint8	plugNeed2CheckFlag;			/* 1: need to check; 0: do not need to check */
	uint32	plugConfigChangeReportValue;	/* init plug parameter */
}tsPlugReportMsg;

typedef struct
{
	uint32	otaImageVersion;
	uint16	otaImageType;
	uint16	otaImageManufactureCode;
	uint8	otaImageBufferSize;
	uint32	otaImageTotalSize;
}tsOtaImageMsg;

typedef struct
{
	uint8	addrMode;
	uint16	saddr;
	uint8	sqn;
	uint32	fileOffset;
	uint32	fileVersion;
	uint16	manuCode;
	uint8	blockSize;
	uint16	imageType;
}tsOtaBlockMsg;

typedef struct
{
	uint8	addrMode;
	uint16	saddr;
	uint8	sqn;
	uint32	currentTime;
	uint32	requestTime;
	uint16	blockDelayMs;
}tsOtaBlockDelayMsg;

typedef struct 
{
	uint16	saddr;
	uint32	otaRequestCount;
}tsOTALimitEndDeviceMsg;

typedef struct 
{
	uint32 readTaskCount;
	uint32 writeTaskCount;
	pthread_mutex_t readTaskCountLock;
	pthread_mutex_t writeTaskCountLock;
}tsRS232TaskCount;

#define APPLY_MEMORY_AND_CHECK(pMemory,memorySize) { \
	pMemory = NULL;\
	pMemory = (char*)malloc(memorySize);\
	if (pMemory == NULL)\
	{\
		_DBG("ERROR: malloc memory by file:%s, func:%s, line:%d.\n", __FILE__, __FUNCTION__, __LINE__);\
		return ;\
	}}

#define FREE_APPLY_MEMORY(pMemory) {\
	if (pMemory != NULL)\
	{\
		free(pMemory);\
		pMemory = NULL;\
	}\
	}

#define MEMSET_STRING(stringBuf,len){\
		memset(stringBuf, '\0', len);\
	}

//#define DEBUG_LOCK
#ifdef DEBUG_LOCK
#define ADD_LOCK(lockName) {\
		pthread_mutex_lock(&lockName);\
		_DBG("[Get lock]: file:%s, func:%s, line:%d.\n", __FILE__, __FUNCTION__, __LINE__);\
	}
#define FREE_LOCK(lockName) {\
		pthread_mutex_unlock(&lockName);\
		_DBG("[Free lock]: file:%s, func:%s, line:%d.\n", __FILE__, __FUNCTION__, __LINE__);\
	}
#else
#define ADD_LOCK(lockName) {\
		pthread_mutex_lock(&lockName);\
	}
#define FREE_LOCK(lockName) {\
		pthread_mutex_unlock(&lockName);\
	}
#endif



/*
*	Function statement
*/
char* m_strncpy(char* dstBuf, const char* srcBuf, int cpSize);


#endif
