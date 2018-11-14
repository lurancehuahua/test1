#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include "rs232.h"
#include "zigbee.h"
#include "zigbee_sqlite3.h"
#include "cJSON.h"



//static uint16 MT7688ProgrammerJN5169Status = 0;
const char *firmwareUrl = "/usr/lib/iot/ZigbeeNodeControlBridge_JN5169.bin";
static uint16 oldMajorVersion = 0;
static uint16 s_mt7688updatejn5169Flag = 0;
static uint32 startnetcount = 0;
static uint8 taskDoneStatus = 0;
static uint16 lqiRequestDeviceAddr = 0;
static short lqiResponseDeviceStatus = -1;
static uint8 tmpEndDeviceVersion = 0;
static uint16 tmpEndDeviceSaddr = 0;
static uint8 openNetworkStatus = 0;
static int initProgressTime = 30;
static int getDeviceGroupExistStatus;
static uint8 backupDBswitch = 0;
static uint32 getMT7688VersionTime = 0;
static uint32 getJN5169VersionTime = 0;
static uint32 s_requestDevicePower = 0; 
static uint16 s_wait_update_JN5169 = 0;
static stReportTimeandSwitch stReportTimeandSwitchMsg;
static int s_mt7688_update_jn5169_psta_value = 0;
static uint8 s_need_init_device_flag = 1;
static uint8 s_needBackupDbFlag = 0;
static uint8 s_needAnalysisDataFlag = 0;
static tsPlugReportMsg s_plugWattMsg;   /* plug  abnormal check */
static tsOtaImageMsg s_otaImageMsg;
static char* s_otaFileUrl = "/usr/lib/iot/otaFile.ota";
static unsigned char* sp_ota_image_data = NULL;
static uint16 s_plugAlarmValue = 90;  /* Default plug alarm value is 90% of rated watt */

#define MAX_LOG_FILE_LENGTH (20 * 1024 * 1024)  // 20M*1024*1024 == 52428800
#define WATCHDOG_CHECK_SYSTEM_MEMORY_MAX (10 * 1024 * 1024)  /* 10M, if watchdog check system malloc memory 10M error, maybe system leak more memory */
#define MAX_BUF_LEN   QUEUE_MSG_LEN  //(512)
#define DEFAULT_CHKNUM    0xFF
#define DEFAULT_DELAY_US    (500 * 1000)

#define WRITE_PROCESS
#ifdef WRITE_PROCESS
static int host2node_msgid = -1;
#endif
static int node2host_msgid = -1;
struct rs232_port_t *s_pst232port = NULL;

#define MAX_CBUFFER_LENTH  (1024)
static tsMsgQueueNode s_tsMsgCircleBuffer[MAX_CBUFFER_LENTH] = {0};
static int s_cbufferIndexWrite = 0, s_cbufferIndexRead = 0;

static uint16 s_initDeviceAddr = 0;
static uint32 s_initDeviceMacH = 0;
static uint32 s_initDeviceMacL = 0;
static uint16 s_initDeviceTag = 0;
static teInitDeviceStatus s_initDeviceStatus = E_INIT_WAIT;

static uint32 s_jn5169MacH = 0;  //0x00158D00
static uint32 s_jn5169MacL = 0;  //0x0211AEC8

static int s_clearE2ROMFlag = 0;
static int s_autoProgressJN5169Flag = 0;

static int s_setPlugAlarmStatus = 0;

#undef	OTA_NOT_LIMIT_COUNT
#define OTA_NOT_LIMIT_COUNT (2)
static tsOTALimitEndDeviceMsg a_otaLimitDeviceMsg[OTA_NOT_LIMIT_COUNT] = {0};

/*
*	Test function area
*/
//#define RS232_TASK_COUNT
#ifdef RS232_TASK_COUNT 
static tsRS232TaskCount sRS232TaskCount;
#endif

#define TEST_RS232_TRANSMIT_SPEED
#ifdef TEST_RS232_TRANSMIT_SPEED
static uint32 sTestTransmitSpeedMs = 5000;
#endif

/*
*	Test function area end
*/


#define RESET_BUFFER(BUFFER, BUFFER_LEN) \
do { \
    uint32 nIndex; \
    for (nIndex=0; nIndex<BUFFER_LEN; nIndex++) \
    { \
        BUFFER[nIndex] = 0x0; \
    } \
}while(0);

#define CHECK_JSON_FORM(jsonObj,dst,src) {if (jsonObj != NULL){ \
		(dst) = (src);\
	}}

#define GET_JSON_INT(root,node,keyName,dstObj) {\
	node = NULL;\
	node = cJSON_GetObjectItem(root, keyName);\
	CHECK_JSON_FORM(node,dstObj,node->valueint)\
}


#define DUMP_BUFFER(BUFFER, BUFFER_LEN) \
do { \
    uint32 nIndex; \
    ZG_INFO("Dump Buffer, len = %d\n", BUFFER_LEN); \
    for (nIndex=0; nIndex<BUFFER_LEN; nIndex++) \
    { \
        ZG_INFO("0x%02x ", BUFFER[nIndex]); \
    } \
    ZG_INFO("\n"); \
}while(0);

extern int report_msg2_server(char* sendMsgBuf, char* serverIp, uint16 serverPort, char* buf);
extern char* MD5_string(const char* srcBuf, int md5_len);


#define REPORT_2SERVER(sendMsgBuf,serverIp,serverPort,readServerResponseBuf) {		\
		ZG_DEBUG("sql get: %s\n", sendMsgBuf);\
		if (report_msg2_server(sendMsgBuf, serverIp, serverPort, readServerResponseBuf) == -1)\
    	{\
			ZG_DEBUG("Error: ZGW can not report data to server.\n");\
			return -1;\
		}}

static uint8 chksum(const uint8 *buf, uint32 buf_len);
static uint32
cmd2serial(const uint8 *buf, uint32 buf_len,
           uint8 *outbuf, uint32 *outbuf_len);

static uint32
serial2cmd(const uint8 *buf, uint32 buf_len,
           uint8 *outbuf, uint32 *outbuf_len);

static int read_ex(uint8 *buf, uint32 buf_len);
static int write_ex(uint8 *buf, uint32 buf_len);
static void processHost2NodeMsg(void);
static void processNode2HostMsg(void);
static int sendMsg(uint8 *buf, uint32 buf_len);

static teMsgEventStatus analyseData(uint8 *buf, uint16 buf_len);
static void processData(void);
int sendHost2NodeMsg(teMsgType emsgType, uint8 *pu8MsgBuf, uint16 buf_len);
int setSystemTime(char *dt);

void requestEndDeviceInit(void);
void requestEndDeviceEnergy(void);
void backupDB(void);
void rebootSystem(void);
void startZigbeeNet(void);

emReturnStatus initZigbee(void);
emReturnStatus initUart(void);

int zigbee_unusedfun(void);
int MT7688ProgrammerJN5169(void);
int lua_open_network_time(uint8 openNetTime);
int lua_view_group_status(uint8 addrMode, uint16 shortDeviceAddr, uint16 groupNumber);
int lua_set_device_onoff(uint8 addrMode, uint16 shortDeviceAddr, uint8 onoffStatus);
int lua_set_device_lum(uint8 addrMode, uint16 shortDeviceAddr, uint8 lumValue);
int lua_set_device_cct(uint8 addrMode, uint16 shortDeviceAddr, uint16 cctValue);
int lua_set_device_hue(uint8 addrMode, uint16 shortDeviceAddr, uint16 hueValue);
void analysis_http_request(httpRequestMsg* httpMsg, char* receMsgBuf);
void init_http_request_msghead(httpRequestMsg* httpMsg);
char* strtoupper(char* srcBuf);
char* strtolower(char* srcBuf);
int get_config_script_value(void);
int log_zigbee_status(int zigbeeStatus, int zigbeeWatchdog);
int gw_server_handler_enter(char* receMsgBuf, int clientSocketId);
int update_task_run_status(httpRequestMsg* httpMsg, int clientSocketId);
int add_get_device_lqi_task(httpRequestMsg* httpMsg, int clientSocketId);
int control_device_status(httpRequestMsg* httpMsg, int clientSocketId);
int update_report_parameter(httpRequestMsg* httpMsg, int clientSocketId);
int start_MT7688_update_JN5169(int clientSocketId);
int get_MT7688_update_JN5169_status(int clientSocketId);
int modify_gateway_update_request_time(httpRequestMsg* httpMsg, int clientSocketId);
int get_gateway_chip_version(int clientSocketId);
void init_http_request_msghead(httpRequestMsg* httpMsg);
void product_gw_test_loop_bsonoff(void);
int send_ota_block_response(tsOtaBlockMsg* p_otaBlockMsg);
int send_block_delay(tsOtaBlockDelayMsg* p_otaBlockDelay);
int limit_ota_endDevice_request_speed(tsOtaBlockDelayMsg* p_otaBlockDelay);
int reset_limit_ota_device(uint16 sAddr);
void rand_report_init_count(uint32* pa_reportCount);
int lua_get_plug_rated_watt(uint16 sAddr);
int lua_set_plug_alarm_value(uint16 sAddr, uint16 plugAlarmValue);













#define PERIODIC_DELAY_SECONDS   5

#define MAX_DEVICE    47
tsDeviceWebdef s_DeviceWebdefList[MAX_DEVICE] =
{
    {E_ZHA_ONF_SWITCH_PROFILE_ID, 120, "ONF Switch"},
    {E_ZHA_LEVEL_CONTROL_SWITCH_PROFILE_ID, 120, "Level Switch"},
    {E_ZHA_ONF_OUTPUT_PROFILE_ID, 65, "ONF Output"},
    {E_ZHA_LEVEL_CONTROL_OUTPUT_PROFILE_ID, 120, "Level Output"},
    {E_ZHA_SCENE_SELECTOR_PROFILE_ID, 120, "Set Scene"},
    {E_ZHA_CONFIGURATION_TOOL_PROFILE_ID, 120, "Conf Tool"},
    {E_ZHA_REMOTE_CONTROL_PROFILE_ID, 120, "Remote Ctl"},
    {E_ZHA_COMBINED_INTERFACE_PROFILE_ID, 120, "Combine Itf"},
    {E_ZHA_RANGE_EXTENDER_PROFILE_ID, 120, "Range Extender"},
    {E_ZHA_MAINS_POWER_OUTLET_PROFILE_ID, 120, "Power Outlet"},
    {E_ZHA_DOOR_LOCK_PROFILE_ID, 120, "Door Lock"},
    {E_ZHA_DOOR_LOCK_CONTROLLER_PROFILE_ID, 120, "Door Lock-CTL"},
    {E_ZHA_SIMPLE_SENSOR_PROFILE_ID, 120, "Sensor"},
    {E_ZHA_CONSUMPTION_AWARENESS_PROFILE_ID, 120, "Consump Dev"},

    {E_ZHA_ONF_PLUG_PROFILE_ID, 65, "Light Plug"},

    {E_ZHA_HOME_GATEWAY_PROFILE_ID, 120, "Home Gateway"},
    {E_ZHA_SMART_PLUG_PROFILE_ID, 65, "Smart Plug"},
    {E_ZHA_WHITE_GOODS_PROFILE_ID, 120, "White Goods"},
    {E_ZHA_METER_INTERFACE_PROFILE_ID, 120, "Meter Itf"},

    {E_ZHA_ONF_LIGHT_PROFILE_ID, 61, "ONF Light"},
    {E_ZHA_DIMMABLE_LIGHT_PROFILE_ID, 62, "Dim Light"},
    {E_ZHA_COLOR_DIMMABLE_LIGHT_PROFILE_ID, 64, "Co-Dim Light"},
    {E_ZHA_ONF_LIGHT_SWITCH_PROFILE_ID, 120, "ONF Switch"},
    {E_ZHA_DIMMER_SWITCH_PROFILE_ID, 120, "Dim Switch"},
    {E_ZHA_COLOR_DIMMER_SWITCH_PROFILE_ID, 120, "Co-Dim Switch"},
    {E_ZHA_LIGHT_SENSOR_PROFILE_ID, 120, "Light Sensor"},
    {E_ZHA_OCCUPANCY_SENSOR_PROFILE_ID, 120, "Ocp Sensor"},

    {E_Z30_ONF_BALLAST_PROFILE_ID, 61, "ONF ballast"},
    {E_Z30_DIMMABLE_BALLAST_PROFILE_ID, 62, "Dim ballast"},
    {E_Z30_ONF_PLUGIN_PROFILE_ID, 65, "Smart plug"},
    {E_Z30_DIMMABLE_PLUGIN_PROFILE_ID, 65, "Smart plug"},
    {E_Z30_COLOR_TEMPERATURE_LIGHT_PROFILE_ID, 63, "CCT Light"},
    {E_Z30_EXTENDED_COLOR_LIGHT_PROFILE_ID, 64, "RGB Light"},
    {E_Z30_LIGHT_LEVEL_SENSOR_PROFILE_ID, 120, "Level sensor"},

    {E_ZLL_DIMMABLE_PLUGIN_PROFILE_ID, 65, "Smart Plug"},
    {E_ZLL_COLOR_LIGHT_PROFILE_ID, 64, "RGB Light"},
    {E_ZLL_EXTENDED_COLOR_LIGHT_PROFILE_ID, 64, "RGB Light"},
    {E_ZLL_COLOR_TEMPERATURE_LIGHT_PROFILE_ID, 63, "CCT Light"},

    {E_ZLL_COLOR_CONTROLLER_PROFILE_ID, 71, "Co-Controller"},
    {E_ZLL_COLOR_SCENE_CONTROLLER_PROFILE_ID, 71, "Co-Controller"},
    {E_ZLL_NONCOLOR_CONTROLLER_PROFILE_ID, 72, "Nco-Controller"},
    {E_ZLL_NONCOLOR_SCENE_CONTROLLER_PROFILE_ID, 72, "Nco-Controller"},
    {E_ZLL_CONTROL_BRIDGE_PROFILE_ID, 120, "CTL-Bridge"},
    {E_ZLL_ONF_SENSOR_PROFILE_ID, 120, "ONF Sensor"},

    {E_ZLL_ONF_LIGHT_PROFILE_ID, 61, "ONF Light"},
    {E_ZLL_ONF_PLUGIN_PROFILE_ID, 65, "Smart Plug"},
    {E_ZLL_DIMMABLE_LIGHT_PROFILE_ID, 62, "Dim Light"},
};

/* snprintf will auto write '\0' to last character, but strncpy not, so we need to do this operator */
char* m_strncpy(char* dstBuf, const char* srcBuf, int cpSize)
{
	strncpy(dstBuf, srcBuf, cpSize);
	dstBuf[cpSize - 1] = '\0';
	return dstBuf;
}


int get_linux_file_size(const char* filename)
{
	struct stat statbuff;

	stat(filename, &statbuff);
	return statbuff.st_size;
}

void get_systemtime_to_logfile(void)
{
	time_t t;
	struct tm* local;

	t = time(NULL);
	local = localtime(&t);
	printf("[%4d-%02d-%02d--%02d:%02d:%02d] "
		,local->tm_year+1900,local->tm_mon+1,local->tm_mday,local->tm_hour,local->tm_min,local->tm_sec);
}

emReturnStatus init_report_msg_struct(void)
{
	int tryCount = 0;
	do 
	{
		if (sql_init_report_msg_struct(&stReportTimeandSwitchMsg) == 0)
		{
			_DBG("INIT report struct successful:\n"
				"powt:%d\n"
				"pows:%d\n"
				"devt:%d\n"
				"devs:%d\n"
				"ndevt:%d\n"
				"ndevs:%d\n"
				,stReportTimeandSwitchMsg.powerTime
				,stReportTimeandSwitchMsg.powerSwitch
				,stReportTimeandSwitchMsg.deviceChangeTime
				,stReportTimeandSwitchMsg.deviceChangeStatus
				,stReportTimeandSwitchMsg.addDeviceTime
				,stReportTimeandSwitchMsg.addDeviceSwitch);
			return RE_SUCCESSFUL;
		}
	}
	while (++tryCount <= 3);

	// get DB error, init next parameter on report
	stReportTimeandSwitchMsg.powerTime = 3600;  // 1h
	stReportTimeandSwitchMsg.powerSwitch = 1;  // ON
	stReportTimeandSwitchMsg.deviceChangeTime = 300; // 5 min
	stReportTimeandSwitchMsg.deviceChangeStatus= 1; // ON
	stReportTimeandSwitchMsg.addDeviceTime = 10;  // 10 seconds
	stReportTimeandSwitchMsg.addDeviceSwitch = 0; //OFF
	return RE_ERROR;
}

int update_report_msg_struct(httpRequestMsg * httpMsg)
{
	stReportTimeandSwitchMsg.powerTime			= REPLACE_GREATER_THAN_ZERO(httpMsg->reportMsg.powerTime,3600);
	stReportTimeandSwitchMsg.powerSwitch		= REPLACE_GREATER_THAN_ZERO(httpMsg->reportMsg.powerSwitch,0);
	stReportTimeandSwitchMsg.deviceChangeTime	= REPLACE_GREATER_THAN_ZERO(httpMsg->reportMsg.deviceStatusTime,300);
	stReportTimeandSwitchMsg.deviceChangeStatus = REPLACE_GREATER_THAN_ZERO(httpMsg->reportMsg.deviceStatusSwitch,0);
	stReportTimeandSwitchMsg.addDeviceTime		= REPLACE_GREATER_THAN_ZERO(httpMsg->reportMsg.addDeviceTime,10);
	stReportTimeandSwitchMsg.addDeviceSwitch	= REPLACE_GREATER_THAN_ZERO(httpMsg->reportMsg.addDeviceSwitch,0);

	_DBG("UPDATE report struct successful:\n"
				"powt:%d\n"
				"pows:%d\n"
				"devt:%d\n"
				"devs:%d\n"
				"ndevt:%d\n"
				"ndevs:%d\n"
				,stReportTimeandSwitchMsg.powerTime
				,stReportTimeandSwitchMsg.powerSwitch
				,stReportTimeandSwitchMsg.deviceChangeTime
				,stReportTimeandSwitchMsg.deviceChangeStatus
				,stReportTimeandSwitchMsg.addDeviceTime
				,stReportTimeandSwitchMsg.addDeviceSwitch);

	return 0;
}

char* strtoupper(char* srcBuf)
{
	int srcLen = strlen(srcBuf);
	int i = 0;
	char* p_dstBuf = NULL;

	if (srcLen == 0) return NULL;
	if ((p_dstBuf = (char*)malloc(srcLen+1)) == NULL) return NULL;

	for (i = 0; i < srcLen; i++)
	{
		p_dstBuf[i] = toupper(srcBuf[i]);
	}
	p_dstBuf[i] = '\0';

	memset(srcBuf, '\0', srcLen);
	strcpy(srcBuf, p_dstBuf);
	
	if (p_dstBuf != NULL) free(p_dstBuf);
	return srcBuf;
}

char* strtolower(char* srcBuf)
{
	int srcLen = strlen(srcBuf);
	int i = 0;
	char* p_dstBuf = NULL;

	if (srcLen == 0) return NULL;
	if ((p_dstBuf = (char*)malloc(srcLen+1) )== NULL) return NULL;

	for (i = 0; i < srcLen; i++)
	{
		p_dstBuf[i] = tolower(srcBuf[i]);
	}
	p_dstBuf[i] = '\0';

	memset(srcBuf, '\0', srcLen);
	strcpy(srcBuf, p_dstBuf);
	
	if (p_dstBuf != NULL) free(p_dstBuf);
	return srcBuf;
}

int get_config_script_value(void)
{
	FILE* fd;
	char getItemName[SIZE_256B] = "\0";
	int getItemValue = 0;

	if ((fd = fopen("/root/progressMT7688/configScript.txt", "r")) == NULL)
	{
		_DBG("fopen configScript error.\n");
		return -1;
	}
	_DBG("OPEN configScript ok.\n");

	MEMSET_STRING(getItemName,SIZE_256B)

	while (fscanf(fd, "%s %d", getItemName, &getItemValue) != EOF)
	{
		_DBG("[GET configScript.txt] Item:%s, value:%d\n", getItemName, getItemValue);
		if (strcmp(getItemName, "clearE2ROM") == 0
			&& (getItemValue == 0 || getItemValue == 1))
		{
			_DBG("set clear E2ROM: %s, %d\n", getItemName, getItemValue);
			s_clearE2ROMFlag = getItemValue;

			sql_set_JN5169_clear_E2ROM(s_clearE2ROMFlag);
		}

		if (strcmp(getItemName, "autoUpdateJN5169") == 0
			&& (getItemValue == 0 || getItemValue == 1))
		{
			_DBG("set auto update JN5169: %s, %d\n", getItemName, getItemValue);
			s_autoProgressJN5169Flag = getItemValue;
		
			if ((getItemValue == 1) && (sql_start_MT7688_update_JN5169() != 0))
			{
				_DBG("[ERROR]:Set auto update JN5169 DB flag.\n");
				fclose(fd);
				return -1;
			}
		}
		
		MEMSET_STRING(getItemName,SIZE_256B)
	}

	fclose(fd);
	return 0;
}

int log_zigbee_status(int zigbeeStatus, int zigbeeWatchdog)
{
	FILE* fd;

	system("chmod -R 777 /tmp/logZigbee.txt");
	if ((fd = fopen("/tmp/logZigbee.txt", "w")) == NULL)
	{
		_DBG("fopen logZigbee.txt error.\n");
		return -1;
	}
	//_DBG("OPEN logZigbee.txt ok.\n");

	fprintf(fd, "%s %d\n", "zigbeeRunCount", zigbeeWatchdog);
	fprintf(fd, "%s %d\n", "zigbeeRunStatus", zigbeeStatus);

	fclose(fd);
	return 0;
}

typedef void (*sighandler_t)(int);
int pox_system(const char *cmd_line)
{
	int ret = 0;
	sighandler_t old_handler;
	
	old_handler = signal(SIGCHLD, SIG_DFL);
	ret = system(cmd_line);
	signal(SIGCHLD, old_handler);
	return ret;
}

/*
*	return:  0 file exist
*		      -1 file not exist
*/
int is_file_exist(const char* file_path)
{
	if (file_path == NULL)
	{
		return -1;
	}

	if (access(file_path, F_OK) == 0)
	{
		return 0;
	}
	return -1;
}

/*
*	return:  0     exist
*			-1  not exist
*/
int is_dir_exist(const char* dir_path)
{
	if (dir_path == NULL)
	{
		return -1;
	}

	if (opendir(dir_path) == NULL)
	{
		return -1;
	}
	return 0;
}

//used to remove compile warnings
int zigbee_unusedfun(void)
{
    write_ex('\0', 1);
    processHost2NodeMsg();
    sendMsg('\0', 1);

    return 0;
}

void reset_integer_array(int arr[], int arrLength)
{
    int i;
    for (i = 0; i < arrLength; i++)
    {
        arr[i] = 0;
    }
}


uint16 s_deviceaddrlist[MAX_DEV_NUM] = {0};
uint16 s_deviceTagList[MAX_DEV_NUM] = {0};
uint8 s_deviceflag[MAX_DEV_NUM] = {0};
uint32 s_deviceaddrnum = 0;
uint32 s_resetflag = 0;

static int _resetDeviceFlag(void)
{
    int i;

    for (i=0; i<MAX_DEV_NUM; i++)
    {
        s_deviceflag[i] = 0;
    }
    return 0;
}

static int _setDeviceFlag(uint16 addr)
{
    int i;
    s_resetflag++;
    for (i=0; i<s_deviceaddrnum; i++)
    {
        if (s_deviceaddrlist[i] == addr)
        {
            s_deviceflag[i]++;
            ZG_DBG("i, addr, flag, resetflag = %d, %d, %d, %d\n", i, addr, s_deviceflag[i], s_resetflag);
            return 0;
        }
    }
    return 0;
}


static int getDeviceWebdef(teDeviceProfileId teDeviceId, tsDeviceWebdef *psDeviceWebdef)
{
    int i;

    for (i=0; i<MAX_DEVICE; i++)
    {
        if (s_DeviceWebdefList[i].teDeviceId == teDeviceId)
        {
            memcpy(psDeviceWebdef, &s_DeviceWebdefList[i], sizeof(tsDeviceWebdef));
            return 0;
        }
    }

    psDeviceWebdef->teDeviceId = teDeviceId;
    psDeviceWebdef->tag = 120;
    strcat(psDeviceWebdef->name, "Unknown Device");
    return 1;
}


static uint8 chksum(const uint8 *buf, uint32 buf_len)
{
    int i = 0;
    uint8 u8crc = 0;

    if ((buf == NULL) || (buf_len > MAX_BUF_LEN))
    {
        return 0xFF;
    }

    u8crc = buf[0];

    for (i=1; i<4; i++)
    {
        u8crc ^= buf[i];
    }

    for (i=5; i<buf_len; i++)
    {
        u8crc ^= buf[i];
    }

    return u8crc;
}


/*
    outbuf should be 256 bytes
*/
static uint32
cmd2serial(const uint8 *buf, uint32 buf_len,
           uint8 *outbuf, uint32 *outbuf_len)
{
#define SL_START_CHAR          0x01
#define SL_ESC_CHAR            0x02
#define SL_END_CHAR            0x03

    uint32 i = 0, bufindex = 0;
    uint8 u8crc = 0;
    uint8 tmpbyte = 0;
    uint8 *pOutbuf = NULL;

    if ((buf == NULL) || (buf_len > MAX_BUF_LEN) || (outbuf == NULL) || (outbuf_len == NULL))
    {
        return 1;
    }

    pOutbuf = outbuf;
    *outbuf_len = 0;

    u8crc = chksum(buf, buf_len);

    pOutbuf[bufindex++] = SL_START_CHAR;

    for (i=0; i<buf_len; i++)
    {
        tmpbyte = buf[i];
        if (i == 4)
        {
            tmpbyte = u8crc;
        }

        if (tmpbyte < 0x10)
        {
            tmpbyte ^= 0x10;
            pOutbuf[bufindex++] = SL_ESC_CHAR;
        }
        pOutbuf[bufindex++] = tmpbyte;
    }

    pOutbuf[bufindex++] = SL_END_CHAR;

    *outbuf_len = bufindex;

    return 0;
}


/*
    outbuf should be 256 bytes
*/
static uint32
serial2cmd(const uint8 *buf, uint32 buf_len,
           uint8 *outbuf, uint32 *outbuf_len)
{
#define SL_START_CHAR          0x01
#define SL_ESC_CHAR            0x02
#define SL_END_CHAR            0x03

    uint32 i = 0, bufindex = 0;
    uint8 u8crc = 0;
    uint8 tmpbyte = 0;
    uint8 escflag = 0;
    uint8 *pOutbuf = NULL;

    if ((buf == NULL) || (buf_len > MAX_BUF_LEN) || (outbuf == NULL) || (outbuf_len == NULL))
    {
        return 1;
    }

    pOutbuf = outbuf;
    *outbuf_len = 0;

//#define COMB_READ_DATA
#ifdef COMB_READ_DATA
    static uint8 combBuf[MAX_BUF_LEN]= {0};
    static uint32 combBuf_len = 0;
    static uint8 startflag = 0;

    do
    {
        if (buf[0] == SL_START_CHAR)
        {
            startflag = 1;
            combBuf_len = 0;
            for (i=0; i<MAX_BUF_LEN; i++)
            {
                combBuf[i] = 0;
            }
        }
        for (i=0; i<buf_len; i++)
        {
            combBuf[combBuf_len++] = buf[i];
        }
        if (buf[buf_len-1] == SL_END_CHAR)
        {
            startflag = 2;
        }
        if (startflag == 1)
        {
            return 4;
        }
    }
    while(0);

    buf = combBuf;
    if ((combBuf[0] != SL_START_CHAR) || (combBuf[combBuf_len-1] != SL_END_CHAR))
    {
        return 2;
    }

    for (i=1; i<(combBuf_len-1); i++)
#else
    if ((buf[0] != SL_START_CHAR) || (buf[buf_len-1] != SL_END_CHAR))
    {
        return 2;
    }
    for (i=1; i<(buf_len-1); i++)
#endif
    {
        tmpbyte = buf[i];
        if (tmpbyte == SL_ESC_CHAR)
        {
            escflag = 1;
            continue;
        }
        if (escflag == 1)
        {
            escflag = 0;
            tmpbyte ^= 0x10;
        }
        pOutbuf[bufindex++] = tmpbyte;
    }

    *outbuf_len = bufindex;

    u8crc = chksum(pOutbuf, bufindex);

    if (u8crc != pOutbuf[4])
    {
        return 3;
    }

    return 0;
}


static int read_ex(uint8 *buf, uint32 buf_len)
{
#define SL_START_CHAR          0x01
#define SL_END_CHAR            0x03

    uint8 cmdBuf[MAX_BUF_LEN] = {0}, sCmdBuf[MAX_BUF_LEN] = {0};
    uint32 cmdBuf_len = 0, sCmdBuf_len = 0, sretVal = 0, read_len = 0, retVal = 0;
    uint8 readByte, startFlag = 0;
    int i, tryTime = MAX_BUF_LEN;

    if ((buf == NULL) || (buf_len < MAX_BUF_LEN))
    {
        ZG_DEBUG("buf is NULL or buf_len less than MAX_BUF_LEN.\n");
        return -1;
    }

    if (!s_mt7688updatejn5169Flag)
    {
        //ZG_DEBUG("--> read_ex is work.\n");
        while (tryTime-- > 0)
        {
            if (s_pst232port == NULL) break;
            //retVal = rs232_read(s_pst232port, &readByte, 1, &read_len);
            retVal = rs232_read_timeout(s_pst232port, &readByte, 1, &read_len, 100);

            if (retVal == RS232_ERR_TIMEOUT)
            {
                if (s_mt7688updatejn5169Flag == 1)
                {
                    break; // relieve the baud
                }
                continue;
            }
            else if (retVal != 0)
            {
                return -1;
            }
            else
            {
                /* if start read is middle of message , then loop read until next message and then handle*/
                if ((startFlag == 0) && (readByte != SL_START_CHAR))
                {
                    continue;
                }

                if (readByte == SL_START_CHAR)
                {
                    startFlag = 1;
                }

                if (readByte == SL_END_CHAR)
                {
                    startFlag = 2;
                }

                sCmdBuf[sCmdBuf_len++] = readByte;

                /* read a full message*/
                if (startFlag == 2)
                {
				    #ifdef DBG_RS232_DATA
						_DBG("read_len=%d hex='%s' ascii='%s'\n", sCmdBuf_len,
							rs232_hex_dump(sCmdBuf, sCmdBuf_len),
							rs232_ascii_dump(sCmdBuf, sCmdBuf_len));
					#endif
				
                    sretVal = serial2cmd(sCmdBuf, sCmdBuf_len, cmdBuf, &cmdBuf_len);
                    if (sretVal == 0)
                    {
                        //ZG_DEBUG("\nread_ex: ");
 
                        for (i=0; i<cmdBuf_len; i++)
                        {
                            buf[i] = cmdBuf[i];
                            //ZG_DEBUG(" %x", buf[i]);
                        }
                        //ZG_DEBUG("\n");
                        return cmdBuf_len;
                    }
                    return -1;
                }
            }
        }
    }

    return -1;
}


/*
    input param: buf, eg data(permit join):  00 49(Type) 00 04(Len) 44(Chksum) FF FC 0A 00(Data)
*/
static int write_ex(uint8 *buf, uint32 buf_len)
{
    uint8 sCmdBuf[MAX_BUF_LEN] = {0};
    uint32 sCmdBuf_len = 0, write_len = 0;
    int retVal = 0;
    //int i = 0;

    if (!s_mt7688updatejn5169Flag)
    {
        //ZG_DEBUG("write_ex is work.\n");
        cmd2serial(buf,buf_len,sCmdBuf,&sCmdBuf_len);
		
        //retVal = rs232_write(s_pst232port, sCmdBuf, sCmdBuf_len, &write_len);
        retVal = rs232_write_timeout(s_pst232port, sCmdBuf, sCmdBuf_len, &write_len, 50);
        if (retVal == RS232_ERR_TIMEOUT)
        {
            ZG_DEBUG("rs232_write_timeout: 50ms.\n");
        }
    }

    return retVal;

}


static void processHost2NodeMsg(void)
{
#ifdef WRITE_PROCESS
    tsMsgQueueNode tsMsgHostData;

    ZG_DBG("Host -> Node: running ..\n");

    while(1)
    {
        if(msgrcv(host2node_msgid,(void*)&tsMsgHostData, sizeof(tsMsgQueueNode), 0, 0) == -1)
        {
            //ZG_DBG("Host -> Node: msgrcv fail\n");
            continue;
        }

        //ZG_DBG("Host -> Node: data, date_len = {0x%02x, %d} \n", tsMsgHostData.data[2], tsMsgHostData.data_len);
	
        write_ex(tsMsgHostData.data, tsMsgHostData.data_len);

#ifdef RS232_TASK_COUNT
		ADD_LOCK(sRS232TaskCount.writeTaskCountLock)
		sRS232TaskCount.writeTaskCount--;
		_DBG("write writeTaskCount: %d\n", sRS232TaskCount.writeTaskCount);
		FREE_LOCK(sRS232TaskCount.writeTaskCountLock)
#endif

        usleep(1000*100);
    }
#endif
}


static void processNode2HostMsg(void)
{
    uint8 buf[MAX_BUF_LEN] = {0};
    uint16 buf_len = 0;

    tsMsgQueueNode tsNodeMsg;

    int retVal = 0;

    ZG_DBG("Host <- Node: running ..\n");

    while(1)
    {
        memset(buf, 0, MAX_BUF_LEN);
        buf_len = 0;

        retVal = read_ex(buf, MAX_BUF_LEN);
        if(retVal != -1)
        {
            buf_len = retVal;

            tsNodeMsg.msg_type = 1;
            tsNodeMsg.data_len = buf_len;
            memcpy(tsNodeMsg.data, buf, buf_len);
			
#ifdef RS232_TASK_COUNT
			ADD_LOCK(sRS232TaskCount.readTaskCountLock)
			sRS232TaskCount.readTaskCount++;
			FREE_LOCK(sRS232TaskCount.readTaskCountLock)
#endif

            if(msgsnd(node2host_msgid, (void*)&tsNodeMsg, sizeof(tsMsgQueueNode), 0) == -1)
            {
                ZG_DBG("Host <- Node: msgsnd failed\n");
            }
        }

        //ZG_DEBUG("read loop ing.\n");
        if (s_mt7688updatejn5169Flag)
        {
            sleep(1);
        }
    }
}


/*
    input param: buf, eg data(permit join):  00 49(Type) 00 04(Len) 44(Chksum) FF FC 0A 00(Data)
*/
static int sendMsg(uint8 *buf, uint32 buf_len)
{
#ifdef WRITE_PROCESS
    //DUMP_BUFFER(buf, buf_len);

    tsMsgQueueNode tsMsgTxData;

    tsMsgTxData.msg_type = 1;
    tsMsgTxData.data_len = buf_len;
    memcpy(tsMsgTxData.data, buf, buf_len);

#ifdef RS232_TASK_COUNT
	ADD_LOCK(sRS232TaskCount.writeTaskCountLock)
	sRS232TaskCount.writeTaskCount++;
	FREE_LOCK(sRS232TaskCount.writeTaskCountLock)
#endif

    msgsnd(host2node_msgid, (void*)&tsMsgTxData, sizeof(tsMsgQueueNode), 0);

    // usleep(DEFAULT_DELAY_US);	/* using 115200bps , this is best delay time */
    // usleep(250*1000); /* JN5169 version 187, ok, 1 second send 4 packet */
    usleep(125*1000); /* JN5169 version 187, ok, 1 second send 8 packet */

	// usleep(1125*100); /* JN5169 version 187, ok, 1 second send 9 packet, but socket and panel limit speed not equal. */
    
	// usleep(100*1000); /* JN5169 version 187, ok, 1 second send 1 packet */
    // usleep(625*100); /* JN5169 version 187, ok, 1 second send 1 packet */

#endif

    return 0;
}

void update_ota_image_notify_msg(uint32 u32FileVersion, uint16 u16ImageType
												, uint16 u16ManufacturerCode, uint32 u32TotalImage)
{
	s_otaImageMsg.otaImageVersion = u32FileVersion;
	s_otaImageMsg.otaImageType = u16ImageType;
	s_otaImageMsg.otaImageManufactureCode = u16ManufacturerCode;
	s_otaImageMsg.otaImageTotalSize = u32TotalImage;

	_DBG("Update ota image notify msg: version:0x%x, imageType:0x%x, manuCode:0x%x, imageSize:%d\n"
		,s_otaImageMsg.otaImageVersion
		,s_otaImageMsg.otaImageType
		,s_otaImageMsg.otaImageManufactureCode
		,s_otaImageMsg.otaImageTotalSize
	);
}

int sendHost2NodeMsg(teMsgType emsgType, uint8 *pu8MsgBuf, uint16 buf_len)
{
    uint8 cmdBuf[MAX_BUF_LEN] = {0};
    uint32 cmdBuf_len = 0;

    switch (emsgType)
    {
    case E_SL_MSG_SEND_WAIT_FOR_DATA_PARAMS:
	{
		uint8 offset = 0;
		
		uint8	addrMode = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
		uint16	saddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		/*  u8 srcEndpoit, u8 dstEndpoint*/
		uint8	sqn = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
		/* U8 status */
		uint32	currentTime = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
		uint32	requestTime	= ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
		uint16	blockDelayMs = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);

		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 17, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], addrMode, cmdBuf_len);
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], saddr, cmdBuf_len);
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], sqn, cmdBuf_len);
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0x97, cmdBuf_len);
		ZNC_BUF_U32_UPD( &cmdBuf[cmdBuf_len], currentTime, cmdBuf_len);
		ZNC_BUF_U32_UPD( &cmdBuf[cmdBuf_len], requestTime, cmdBuf_len);
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], blockDelayMs, cmdBuf_len);

		_DBG("Send 0x%x delay time ct:%d, requestT:%d, blockDelay:%d.\n"
			, saddr, currentTime, requestTime, blockDelayMs);
	}
	break;

	case E_SL_MSG_BLOCK_SEND:
	{
		uint8 offset = 0;
		int i = 0;

		uint8 addrMode = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
		uint16 sAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		/* srcEndPoint, DstEndpoint*/
		uint8 sqn = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
		/* status */
		uint32 fileOffset = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
		uint32 fileVersion = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
		uint16 manucode = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint16 imageType = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint8 blockSize = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
		/* block data */
		uint8 msgLen = blockSize + 20;

		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], msgLen, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], addrMode, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], sAddr, cmdBuf_len);
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len); /* src Endpoint */
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len); /* dst Endpoint */
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], sqn, cmdBuf_len);
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len); /* status */
		ZNC_BUF_U32_UPD( &cmdBuf[cmdBuf_len], fileOffset, cmdBuf_len);
		ZNC_BUF_U32_UPD( &cmdBuf[cmdBuf_len], fileVersion, cmdBuf_len);
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], imageType, cmdBuf_len);
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], manucode, cmdBuf_len);
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], blockSize, cmdBuf_len);

		if (blockSize > 0 && blockSize < 110)
		{
			printf("block data: ");
			for (i = 0; i < blockSize; i++)
			{
				cmdBuf[cmdBuf_len+i] = pu8MsgBuf[offset+i];
				printf(" %x", (unsigned char)cmdBuf[cmdBuf_len+i]);
			}
			printf("\n");
			
			cmdBuf_len += blockSize;
		}

		_DBG("Send OTA BLOCK RESPONSE.\n");
	}
	break;

	
	case E_SL_MSG_IMAGE_NOTIFY:
	{
		uint8 offset = 0;	
        uint8 addrMode = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        uint16 sAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint8 blockBufSize = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
		uint32 otaFileVersion = s_otaImageMsg.otaImageVersion;
		uint16 otaImageType = s_otaImageMsg.otaImageType;
		uint16 otaImageManufactureCode = s_otaImageMsg.otaImageManufactureCode;

		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0X0F, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], addrMode, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], sAddr, cmdBuf_len);
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);
		ZNC_BUF_U32_UPD( &cmdBuf[cmdBuf_len], otaFileVersion, cmdBuf_len);
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], otaImageType, cmdBuf_len);
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], otaImageManufactureCode, cmdBuf_len);
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], blockBufSize, cmdBuf_len);

		_DBG("Send ota Image notify.\n");
	}
	break;
	
	
	case E_SL_MSG_LOAD_NEW_IMAGE:
	{
		int i = 0;
		uint8 offset = 0;
		
        uint8 addrMode = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        uint16 sAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		
		uint32 u32FileIdentifier = LN_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
		uint16 u16HeaderVersion = LN_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint16 u16HeaderLength = LN_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint16 u16HeaderControlField = LN_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint16 u16ManufacturerCode = LN_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint16 u16ImageType = LN_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint32 u32FileVersion = LN_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
		uint16 u16StackVersion = LN_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		// 32 * au8OtaFileHeaderString
		uint32 u32TotalImage = LN_RTN_U32_OFFSET(pu8MsgBuf, 32 + offset, offset);
		uint8 u8SecurityCredVersion = LN_RTN_U8_OFFSET(pu8MsgBuf, 32 + offset, offset);
		uint32 low_upgradeFileDest = LN_RTN_U32_OFFSET(pu8MsgBuf, 32 + offset, offset);
		uint32 high_upgradeFileDest = LN_RTN_U32_OFFSET(pu8MsgBuf, 32 + offset, offset);
		uint16 u16MinimumHwVersion = LN_RTN_U16_OFFSET(pu8MsgBuf, 32 + offset, offset);
		uint16 u16MaxHwVersion = LN_RTN_U16_OFFSET(pu8MsgBuf, 32 + offset, offset);

		/* update ota notify msg */
		update_ota_image_notify_msg(u32FileVersion, u16ImageType, u16ManufacturerCode, u32TotalImage);
		
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 72, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], addrMode, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], sAddr, cmdBuf_len);

		ZNC_BUF_U32_UPD( &cmdBuf[cmdBuf_len], u32FileIdentifier, cmdBuf_len);
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], u16HeaderVersion, cmdBuf_len);
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], u16HeaderLength, cmdBuf_len);
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], u16HeaderControlField, cmdBuf_len);
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], u16ManufacturerCode, cmdBuf_len);
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], u16ImageType, cmdBuf_len);
		ZNC_BUF_U32_UPD( &cmdBuf[cmdBuf_len], u32FileVersion, cmdBuf_len);
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], u16StackVersion, cmdBuf_len);

		for (i = 0; i < 32; i++)
		{
			cmdBuf[cmdBuf_len+i] = pu8MsgBuf[23+i];
		}
		//strncat(&cmdBuf[cmdBuf_len], &pu8MsgBuf[23], 32);
		cmdBuf_len += 32;
		ZNC_BUF_U32_UPD( &cmdBuf[cmdBuf_len], u32TotalImage, cmdBuf_len);
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], u8SecurityCredVersion, cmdBuf_len);
		ZNC_BUF_U32_UPD( &cmdBuf[cmdBuf_len], high_upgradeFileDest, cmdBuf_len);
		ZNC_BUF_U32_UPD( &cmdBuf[cmdBuf_len], low_upgradeFileDest, cmdBuf_len);
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], u16MinimumHwVersion, cmdBuf_len);
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], u16MaxHwVersion, cmdBuf_len);
	
		_DBG("Send load ota image data.\n");
	}
	break;

	
	case E_SL_MSG_VIEW_GROUP:
	{
		uint8 offset = 0;
        uint8 addrMode = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        uint16 sAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        uint16 groupNumber = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);

		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0x0007, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], addrMode, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], sAddr, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 255, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], groupNumber, cmdBuf_len);
		
		getDeviceGroupExistStatus = -1;
        _DBG("Send view group: %d, sAddr:%d\n", groupNumber, sAddr);
	}
	break;

	
    case E_SL_MSG_ONOFF_NOEFFECTS:
    {
        uint8 offset = 0;
        uint8 addrMode = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        uint16 sAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        uint8 onoffStatus = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);

        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0x0006, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], addrMode, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], sAddr, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 255, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], onoffStatus, cmdBuf_len);
        _DBG("Send sAddr:%d, onoff:%d\n", sAddr, onoffStatus);
    }
    break;

    case E_SL_MSG_MOVE_TO_LEVEL_ONOFF:
    {
        uint8 offset = 0;
        uint8 addrMode;
        uint16 sAddr;
        uint8 lumValue;

        addrMode = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        sAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        lumValue = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);

        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0x0009, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], addrMode, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], sAddr, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 255, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], lumValue, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 5, cmdBuf_len);
        _DBG("Send sAddr:%d, lum:%d\n", sAddr, lumValue);
    }
    break;

    case E_SL_MSG_MOVE_TO_COLOUR_TEMPERATURE:
    {
        uint8 offset = 0;
        uint8 addrMode;
        uint16 sAddr;
        uint16 cctValue;

        addrMode = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        sAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        cctValue = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);

        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0x0009, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], addrMode, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], sAddr, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 255, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], cctValue, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        _DBG("Send sAddr:%d, cct:%d\n", sAddr, cctValue);
    }
    break;

    case E_SL_MSG_ENHANCED_MOVE_TO_HUE_SATURATION:
    {
        uint8 offset = 0;
        uint8 addrMode;
        uint16 sAddr;
        uint16 hueValue;

        addrMode = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        sAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        hueValue = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);

        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0x000A, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], addrMode, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], sAddr, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 255, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 254, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], hueValue, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        _DBG("Send sAddr:%d, hue:%d\n", sAddr, hueValue);
    }
    break;

    case E_SL_MSG_MANAGEMENT_LEAVE_REQUEST:
    {
        uint8 offset = 0;
        uint16 sAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        uint32 mach = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
        uint32 macl = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);

        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0x000C, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], sAddr, cmdBuf_len);
        ZNC_BUF_U32_UPD( &cmdBuf[cmdBuf_len], mach, cmdBuf_len);
        ZNC_BUF_U32_UPD( &cmdBuf[cmdBuf_len], macl, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);
       // ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);   // this leave child
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        _DBG("Send delete device sAddr:%d, mach:%d, macl:%d\n", sAddr, mach, macl);
    }
    break;

    case E_SL_MSG_IDENTIFY_SEND:
    {
        uint8 addrMode = pu8MsgBuf[0];
        uint16 deviceAddr = ((uint16)pu8MsgBuf[1] << 8) | ((uint16)pu8MsgBuf[2] & 0xFF);
        uint16 identifyTime = ((uint16)pu8MsgBuf[3] << 8) | ((uint16)pu8MsgBuf[4] & 0xFF);

        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0x0007, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], addrMode, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], deviceAddr, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 255, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], identifyTime, cmdBuf_len);
        _DBG("Send device:%d, identify time: %d\n", deviceAddr, identifyTime);

    }
    break;

    case E_SL_MSG_PERMIT_JOINING_REQUEST:
    {
        uint8 openTime = pu8MsgBuf[0];
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0x0004, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0xFFFC, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], openTime, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        _DBG("Send open net time: %d\n", openTime);
    }
    break;

    case E_SL_MSG_MANAGEMENT_LQI_REQUEST:
    {
        uint16 deviceAddr = ((uint16)pu8MsgBuf[0] << 8) | ((uint16)pu8MsgBuf[1] & 0xFF);
        ZG_DEBUG("Send get LQI deviceAddr:%d\n", deviceAddr);

        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0x0003, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], deviceAddr, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);

        lqiRequestDeviceAddr = deviceAddr;
        lqiResponseDeviceStatus = -1;
    }
    break;

    case E_SL_MSG_REMOVE_GROUP:
    {
        uint16 deviceAddr = ((uint16)pu8MsgBuf[0] << 8) | ((uint16)pu8MsgBuf[1] & 0xFF);
        uint16 groupNum = ((uint16)pu8MsgBuf[2] << 8) | ((uint16)pu8MsgBuf[3] & 0xFF);
        ZG_DEBUG("Send deviceAddr:%d, groupNum:%d\n", deviceAddr, groupNum);
        //#define BUF_TO_INT32

        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0x0007, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], E_ZCL_AM_SHORT, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], deviceAddr, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);//u8TargetEndpoint[idevice]
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], groupNum, cmdBuf_len);
    }
    break;

    case E_SL_MSG_ADD_GROUP:
    {
        //ZG_DEBUG("gid_H: %d, gid_L:%d\n", pu8MsgBuf[2], pu8MsgBuf[3]);
        uint16 deviceAddr = ((uint16)pu8MsgBuf[0] << 8) | ((uint16)pu8MsgBuf[1] & 0xFF);
        uint16 groupNum = ((uint16)pu8MsgBuf[2] << 8) | ((uint16)pu8MsgBuf[3] & 0xFF);
        ZG_DEBUG("Send deviceAddr:%d, groupNum:%d\n", deviceAddr, groupNum);

        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0x0007, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], E_ZCL_AM_SHORT, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], deviceAddr, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);//u8TargetEndpoint[idevice]
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], groupNum, cmdBuf_len);
    }
    break;

    case E_SL_MSG_GET_VERSION:
    {
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
    }
    break;

    case E_SL_MSG_ACTIVE_ENDPOINT_REQUEST:
    {
        uint16 u16MsgNwkAddr;
        u16MsgNwkAddr = pu8MsgBuf[0] << 8;
        u16MsgNwkAddr |= pu8MsgBuf[1];
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], emsgType, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 2, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16MsgNwkAddr, cmdBuf_len);
    }
    break;

    case E_SL_MSG_INIT_DEVICE_REQ:
    {
        uint16 u16MsgNwkAddr;

        u16MsgNwkAddr = pu8MsgBuf[0] << 8;
        u16MsgNwkAddr |= pu8MsgBuf[1];
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], emsgType, cmdBuf_len );
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 10, cmdBuf_len );
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16MsgNwkAddr, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], pu8MsgBuf[2], cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], pu8MsgBuf[3], cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], pu8MsgBuf[4], cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], pu8MsgBuf[5], cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], pu8MsgBuf[6], cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], pu8MsgBuf[7], cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], pu8MsgBuf[8], cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], pu8MsgBuf[9], cmdBuf_len);
    }
    break;

    case E_SL_MSG_SIMPLE_DESCRIPTOR_REQUEST:
    {
        uint16 u16MsgNwkAddr;
        uint8 u8MsgEndpoint;
        u16MsgNwkAddr = pu8MsgBuf[2] << 8;
        u16MsgNwkAddr |= pu8MsgBuf[3];
        u8MsgEndpoint = pu8MsgBuf[5];
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], emsgType, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 3, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16MsgNwkAddr, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], u8MsgEndpoint, cmdBuf_len);
    }
    break;

    case E_SL_MSG_MEASUREMENT_ELECTRIC_USE_HOUR_REQ:
    {
        uint16 u16MsgNwkAddr;
        u16MsgNwkAddr = pu8MsgBuf[1] << 8;
        u16MsgNwkAddr |= pu8MsgBuf[0];
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], emsgType, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 11, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16MsgNwkAddr, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 1, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);
    }
    break;

    case E_SL_MSG_MEASUREMENT_ELECTRIC_USE_ENERGE_REQ:
    {
        uint16 u16MsgNwkAddr;
        u16MsgNwkAddr = pu8MsgBuf[1] << 8;
        u16MsgNwkAddr |= pu8MsgBuf[0];
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], emsgType, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 15, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16MsgNwkAddr, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 1, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        ZNC_BUF_U32_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        ZNC_BUF_U32_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);
    }
    break;

    case E_SL_MSG_START_NETWORK:
    {
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], emsgType, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
    }
    break;

    case E_SL_MSG_READ_ATTRIBUTE_REQUEST:
    {
        uint16 u16MsgNwkAddr;
        u16MsgNwkAddr = pu8MsgBuf[1] << 8;
        u16MsgNwkAddr |= pu8MsgBuf[0];
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], emsgType, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 14, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], E_ZCL_AM_SHORT, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], u16MsgNwkAddr, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //source endpoint
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //dest. endpoint
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], ELECTRICAL_MEASUREMENT_CLUSTER_ID, cmdBuf_len );  //clusterId
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //direction, 0-server2client, 1-client2server
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //Manufacturer specific, 0-no
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len );  //Manufacturer id
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //number of attributes
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], ACTIVE_POWER_ATTRIBUTE_ID, cmdBuf_len );  //attributes list[0] ...
    }
    break;

	case E_SL_MSG_READ_ATTRIBUTE_REQUEST_PLUG_RATED_POWER:
    {
		uint32 offset = 0;
        uint16 u16MsgNwkAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], E_SL_MSG_READ_ATTRIBUTE_REQUEST, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 14, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], E_ZCL_AM_SHORT, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], u16MsgNwkAddr, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //source endpoint
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //dest. endpoint
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], ELECTRICAL_MEASUREMENT_CLUSTER_ID, cmdBuf_len );  //clusterId
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //direction, 0-server2client, 1-client2server
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //Manufacturer specific, 0-no
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len );  //Manufacturer id
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //number of attributes
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], PLUG_REAED_WATT_ATTRIBUTE_ID, cmdBuf_len );  //attributes list[0] ...

		_DBG("Send get plug rated watt sAddr: [%d]\n", u16MsgNwkAddr);
    }
    break;

	case E_SL_MSG_READ_PLUG_SET_RATED_VALUE:
	{
		uint32 offset = 0;
        uint16 u16MsgNwkAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], E_SL_MSG_READ_ATTRIBUTE_REQUEST, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 14, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], E_ZCL_AM_SHORT, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], u16MsgNwkAddr, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //source endpoint
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //dest. endpoint
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], ELECTRICAL_MEASUREMENT_CLUSTER_ID, cmdBuf_len );  //clusterId
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //direction, 0-server2client, 1-client2server
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //Manufacturer specific, 0-no
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //Manufacturer id
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //number of attributes
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], PLUG_ALARM_WATT_ATTRIBUTE_ID, cmdBuf_len);  //attributes list[0] ...

		_DBG("Send get plug set alarm value: [%d]\n", u16MsgNwkAddr);
	}
	break;

	case E_SL_MSG_READ_ENDDEVICE_CURRENT_VERSION:
	{
		uint32 offset = 0;
        uint16 u16MsgNwkAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		ZG_DEBUG("Send get EndDevice version :%d\n", u16MsgNwkAddr);
		
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], E_SL_MSG_READ_ATTRIBUTE_REQUEST, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 14, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], E_ZCL_AM_SHORT, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], u16MsgNwkAddr, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //source endpoint
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //dest. endpoint
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len );  //clusterId 0
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //direction, 0-server2client, 1-client2server
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //Manufacturer specific, 0-no
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //Manufacturer id
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //number of attributes
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //attributes ID 1, is get endDevice version

		tmpEndDeviceSaddr = u16MsgNwkAddr;
		tmpEndDeviceVersion = 0;
	}
	break;

	case E_SL_MSG_WRITE_ATRIBUTE_SET_PLUG_ALARM_VALUE:
	{
		uint32 offset = 0;
        uint16 u16MsgNwkAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint16 u16PlugAlarmValue = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], E_SL_MSG_WRITE_ATTRIBUTE_REQUEST, cmdBuf_len); /* 0x0110 */
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 0x13, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], E_ZCL_AM_SHORT, cmdBuf_len);
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], u16MsgNwkAddr, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //source endpoint
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //dest. endpoint
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], ELECTRICAL_MEASUREMENT_CLUSTER_ID, cmdBuf_len );  //clusterId 0x0B04
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //direction, 0-server2client, 1-client2server
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //Manufacturer specific, 0-no
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len );  //Manufacturer id
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //number of attributes
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], PLUG_ALARM_WATT_ATTRIBUTE_ID, cmdBuf_len); //attributes list[0] ...  0xFF00
		ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0x23, cmdBuf_len); 
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);  /* alarm high value */
		ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], u16PlugAlarmValue, cmdBuf_len); /* alarm low value */

		_DBG("Send get plug rated watt sAddr: [%d]\n", u16MsgNwkAddr);
	}
	break;

    case E_SL_MSG_CONFIG_REPORTING_REQUEST:
    {
// #define ELECTRIC_REPORT_INTERVAL_MIN  (60*60)
// #define ELECTRIC_REPORT_INTERVAL_MAX  (ELECTRIC_REPORT_INTERVAL_MIN+2)

#define ELECTRIC_REPORT_INTERVAL_MIN  (0)
#define ELECTRIC_REPORT_INTERVAL_MAX  (60*60)  // cycle report, uint:1s


        uint16 u16MsgLen = 23;
        uint16 u16ClusterId;
        uint8 u8NumberOfAttributesInRequest, eAttributeDataType, zuint8ReportableChange; // 0.1W
        uint16 u16AttributeEnum, u16MinimumReportingInterval, u16MaximumReportingInterval;

        switch (s_initDeviceStatus)
        {
        case E_INIT_START:
            if (s_initDeviceTag == 65)
            {
                s_initDeviceStatus = E_INIT_METERING_REPORT_CONFIG_REQ;
                u16ClusterId = METERING_CLUSTER_ID;	// first bind 0x0702, and then bind 0x0B04
                u8NumberOfAttributesInRequest = 1;
                u16AttributeEnum = CURRENT_SUMMATION_ATTRIBUTE_ID; // 0x0
                eAttributeDataType = 0x25;  //E_ZCL_UINT48
                u16MinimumReportingInterval = ELECTRIC_REPORT_INTERVAL_MIN;
                u16MaximumReportingInterval = ELECTRIC_REPORT_INTERVAL_MAX;
                zuint8ReportableChange = 0;
            }
            else
            {
                s_initDeviceStatus = E_INIT_ONOFF_REPORT_CONFIG_REQ;
                u16ClusterId = ONOFF_CLUSTER_ID;
                u8NumberOfAttributesInRequest = 1;
                u16AttributeEnum = ONOFF_ATTRIBUTE_ID;
                eAttributeDataType = 0x10;  //E_ZCL_BOOL
                u16MinimumReportingInterval = 0;
                u16MaximumReportingInterval = 0;
                zuint8ReportableChange = 1;
            }
            break;

        case E_INIT_ONOFF_BIND_REQ:
            s_initDeviceStatus = E_INIT_LEVEL_REPORT_CONFIG_REQ;
            u16ClusterId = LEVEL_CONTROL_CLUSTER_ID;
            u8NumberOfAttributesInRequest = 1;
            u16AttributeEnum = CURRENT_LEVEL_ATTRIBUTE_ID;
            eAttributeDataType = 0x20;  //E_ZCL_UINT8
            u16MinimumReportingInterval = 0;
            u16MaximumReportingInterval = 0;
            zuint8ReportableChange = 1;
            break;

        case E_INIT_LEVEL_BIND_REQ:
            if (s_initDeviceTag == 63)
            {
                s_initDeviceStatus = E_INIT_COLOR_TEMPERATURE_REPORT_CONFIG_REQ;
                u16ClusterId = COLOR_CONTROL_CLUSTER_ID;
                u8NumberOfAttributesInRequest = 1;
                u16AttributeEnum = COLOR_TEMPERATURE_MIREDS_ATTRIBUTE_ID;
                eAttributeDataType = 0x21;  //E_ZCL_UINT16
                u16MinimumReportingInterval = 0;
                u16MaximumReportingInterval = 0;
                zuint8ReportableChange = 1;
            }
            else if (s_initDeviceTag == 64)
            {
                s_initDeviceStatus = E_INIT_COLOR_REPORT_CONFIG_REQ;
                u16ClusterId = COLOR_CONTROL_CLUSTER_ID;
                u8NumberOfAttributesInRequest = 1;
                u16AttributeEnum = CURRENT_HUE_ATTRIBUTE_ID;
                eAttributeDataType = 0x20;  //E_ZCL_UINT8
                u16MinimumReportingInterval = 0;
                u16MaximumReportingInterval = 0;
                zuint8ReportableChange = 1;
            }
            break;

        case E_INIT_METERING_BIND_REQ:
            s_initDeviceStatus = E_INIT_ELECTRICAL_MEASUREMENT_REPORT_CONFIG_REQ;
            u16ClusterId = ELECTRICAL_MEASUREMENT_CLUSTER_ID;  // 0x0B04
            u8NumberOfAttributesInRequest = 2;
            u16AttributeEnum = ACTIVE_POWER_ATTRIBUTE_ID; // 0x050B
            eAttributeDataType = 0x29;  //E_ZCL_INT16
            u16MinimumReportingInterval = ELECTRIC_REPORT_INTERVAL_MIN;
            u16MaximumReportingInterval = ELECTRIC_REPORT_INTERVAL_MAX;
            zuint8ReportableChange = 0x60;  /* plug change report */
            u16MsgLen += 11;
            break;

        default:
            return 0;
        }

        ZG_DBG(">> Config Report(addr=%x, u16ClusterId = 0x%x)\n", s_initDeviceAddr, u16ClusterId);

        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], emsgType, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16MsgLen, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], E_ZCL_AM_SHORT, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], s_initDeviceAddr, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //u8SourceEndPointId
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //u8DestinationEndPointId
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16ClusterId, cmdBuf_len);  //u16ClusterId
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len); //bDirectionIsServerToClient
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //bIsManufacturerSpecific
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //u16ManufacturerCode
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], u8NumberOfAttributesInRequest, cmdBuf_len);  //u8NumberOfAttributesInRequest

        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len); //u8DirectionIsReceived
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], eAttributeDataType, cmdBuf_len); //eAttributeDataType
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16AttributeEnum, cmdBuf_len);  //u16AttributeEnum
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16MinimumReportingInterval, cmdBuf_len);  //u16MinimumReportingInterval
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16MaximumReportingInterval, cmdBuf_len);  //u16MaximumReportingInterval
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //u16TimeoutPeriodField
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], zuint8ReportableChange, cmdBuf_len);  //zuint8ReportableChange

        if (u8NumberOfAttributesInRequest == 2)
        {
            u16AttributeEnum = MAN_SPEC_DIVISOR_ATTRIBUTE_ID;
            eAttributeDataType = 0x21;  //E_ZCL_UINT16
            u16MinimumReportingInterval = ELECTRIC_REPORT_INTERVAL_MIN;
            u16MaximumReportingInterval = ELECTRIC_REPORT_INTERVAL_MAX;
            zuint8ReportableChange = 0;
            ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len); //u8DirectionIsReceived
            ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], eAttributeDataType, cmdBuf_len); //eAttributeDataType
            ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16AttributeEnum, cmdBuf_len);  //u16AttributeEnum
            ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16MinimumReportingInterval, cmdBuf_len);  //u16MinimumReportingInterval
            ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16MaximumReportingInterval, cmdBuf_len);  //u16MaximumReportingInterval
            ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);  //u16TimeoutPeriodField
            ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], zuint8ReportableChange, cmdBuf_len);  //zuint8ReportableChange
        }
    }
    break;

    case E_SL_MSG_BIND:
    {
        uint16 u16ClusterId;
        switch (s_initDeviceStatus)
        {
        case E_INIT_ONOFF_REPORT_CONFIG_REQ:
            s_initDeviceStatus = E_INIT_ONOFF_BIND_REQ;
            u16ClusterId = ONOFF_CLUSTER_ID;
            break;
        case E_INIT_LEVEL_REPORT_CONFIG_REQ:
            s_initDeviceStatus = E_INIT_LEVEL_BIND_REQ;
            u16ClusterId = LEVEL_CONTROL_CLUSTER_ID;
            break;
        case E_INIT_COLOR_TEMPERATURE_REPORT_CONFIG_REQ:
        case E_INIT_COLOR_REPORT_CONFIG_REQ:
            s_initDeviceStatus = E_INIT_COLOR_BIND_REQ;
            u16ClusterId = COLOR_CONTROL_CLUSTER_ID;
            break;
        case E_INIT_METERING_REPORT_CONFIG_REQ:
            s_initDeviceStatus = E_INIT_METERING_BIND_REQ;
            u16ClusterId = METERING_CLUSTER_ID;
            break;
        case E_INIT_ELECTRICAL_MEASUREMENT_REPORT_CONFIG_REQ:
            s_initDeviceStatus = E_INIT_ELECTRICAL_MEASUREMENT_BIND_REQ;
            u16ClusterId = ELECTRICAL_MEASUREMENT_CLUSTER_ID;
            break;
        default:
            return 0;
        }

        ZG_DBG(">> E_SL_MSG_BIND (ClusterID = 0x%x, addr=%08x %08x,  Gaddr=%08x %08x,)\n", 
            u16ClusterId, s_initDeviceMacH, s_initDeviceMacL, s_jn5169MacH, s_jn5169MacL);

        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], emsgType, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 21, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
        ZNC_BUF_U32_UPD(&cmdBuf[cmdBuf_len], s_initDeviceMacH, cmdBuf_len);
        ZNC_BUF_U32_UPD(&cmdBuf[cmdBuf_len], s_initDeviceMacL, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //target u8Endpoint
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16ClusterId, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], E_ZCL_AM_IEEE, cmdBuf_len);
        ZNC_BUF_U32_UPD(&cmdBuf[cmdBuf_len], s_jn5169MacH, cmdBuf_len);
        ZNC_BUF_U32_UPD(&cmdBuf[cmdBuf_len], s_jn5169MacL, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //destination u8Endpoint
    }
    break;

    case E_SL_MSG_IEEE_ADDRESS_REQUEST:
    {
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], emsgType, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 6, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], 0, cmdBuf_len);
    }
    break;

    default:
        return 0;
    }

    sendMsg(cmdBuf, cmdBuf_len);

#if 0 // for jn5169 couldn't response 0xB04 config report
    if (s_initDeviceStatus == E_INIT_ELECTRICAL_MEASUREMENT_REPORT_CONFIG_REQ)
    {
        uint16 u16ClusterId;

        s_initDeviceStatus = E_INIT_WAIT;
        memset(cmdBuf, 0x00, sizeof(cmdBuf));
        cmdBuf_len = 0;
        u16ClusterId = ELECTRICAL_MEASUREMENT_CLUSTER_ID;

        ZG_DBG(">> E_SL_MSG_BIND (ClusterID = 0x%x, addr=%08x %08x,  Gaddr=%08x %08x,)\n", 
            u16ClusterId, s_initDeviceMacH, s_initDeviceMacL, s_jn5169MacH, s_jn5169MacL);

        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], emsgType, cmdBuf_len);
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], 21, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len);
        ZNC_BUF_U32_UPD(&cmdBuf[cmdBuf_len], s_initDeviceMacH, cmdBuf_len);
        ZNC_BUF_U32_UPD(&cmdBuf[cmdBuf_len], s_initDeviceMacL, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //target u8Endpoint
        ZNC_BUF_U16_UPD(&cmdBuf[cmdBuf_len], u16ClusterId, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], E_ZCL_AM_IEEE, cmdBuf_len);
        ZNC_BUF_U32_UPD(&cmdBuf[cmdBuf_len], s_jn5169MacH, cmdBuf_len);
        ZNC_BUF_U32_UPD(&cmdBuf[cmdBuf_len], s_jn5169MacL, cmdBuf_len);
        ZNC_BUF_U8_UPD(&cmdBuf[cmdBuf_len], 1, cmdBuf_len);  //destination u8Endpoint

        sleep(1);
        sendMsg(cmdBuf, cmdBuf_len);
        sleep(1);
        sql_update_device_ott(s_initDeviceAddr, 1);  // smart plug init finished
    }
#endif
    return 0;
}


static teMsgEventStatus analyseData(uint8 *buf, uint16 buf_len)
{
    extern int sql_update(char* sql);
    static uint16 s_preplugonhour = 0xFFFF;
    static uint32 s_plugrptcount = 0;

    uint16 u16MsgType, u16MsgLen;
    uint8 *pu8MsgBuf = NULL;

    zgw_device_t device;

    //DUMP_BUFFER(buf, buf_len);

    u16MsgType = (buf[0] << 8) | buf[1];
    u16MsgLen = (buf[2] << 8) | buf[3];
    if ((u16MsgLen+5) != buf_len)
    {
        return E_MSG_EVENT_ERROR;
    }

    pu8MsgBuf = &buf[5];

#ifdef RS232_TASK_COUNT
	ADD_LOCK(sRS232TaskCount.readTaskCountLock)
	sRS232TaskCount.readTaskCount--;
	_DBG("analysys readTaskCount:%d\n", sRS232TaskCount.readTaskCount);
	FREE_LOCK(sRS232TaskCount.readTaskCountLock)
#endif

	if (u16MsgType == 0x8000 || u16MsgType == 0x8702) // ignore analysis type
	{
		
		return E_MSG_EVENT_FINISH;
	}
	
	_DBG("Analysis: 0x%x\n", u16MsgType);
	s_needBackupDbFlag = 1;   // ready to backup DB
	s_needAnalysisDataFlag = 1; // ready to analysis msg

    switch(u16MsgType)
    {
#if 0
    case E_SL_MSG_APS_DATA_CONFIRM_FAILED:
    {
    }
    break;
#endif

	case E_SL_MSG_BLOCK_REQUEST:
	{
		uint8 offset = 0;
		tsOtaBlockMsg blockMsg;
		tsOtaBlockDelayMsg otaBlockDelay;
		int ret = 0;

		uint8 sqn = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
		offset += 3;  /* 8:srcEndpoint, 16:clusterId*/
		uint8 sAddrMode = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);		
		uint16 u16SrcAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint32 mac_h = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
		uint32 mac_l = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
		uint32 u32FileOffset = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
		uint32 u32FileVersion = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
		uint16 u16ImageType = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint16 u16ManufactureCode = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint16 u16BlockRequestDelay = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint8 u8MaxDataSize = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
		uint8 u8FieldControl = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);

		_DBG("Get OTA client BLOCK REQUEST:\n"
			"saddr:0x%x, mac:%d%d, offset:%d, fver:%d, imgType:0x%x, manuc:0x%x, delay:0x%x, size:%d, fctl:%d\n"
			,u16SrcAddr,mac_h,mac_l,u32FileOffset,u32FileVersion,u16ImageType
			,u16ManufactureCode,u16BlockRequestDelay,u8MaxDataSize,u8FieldControl
		);

		// analysis send ota image block.
		blockMsg.addrMode = sAddrMode;
		blockMsg.blockSize = u8MaxDataSize;
		blockMsg.fileOffset = u32FileOffset;
		blockMsg.fileVersion = u32FileVersion;
		blockMsg.manuCode = u16ManufactureCode;
		blockMsg.saddr = u16SrcAddr;
		blockMsg.sqn = sqn;
		blockMsg.imageType = u16ImageType;

//#define START_LIMIT_OTA_END_DEVICE_COUNT
#ifdef START_LIMIT_OTA_END_DEVICE_COUNT
		otaBlockDelay.addrMode = sAddrMode;
		otaBlockDelay.saddr = u16SrcAddr;
		otaBlockDelay.sqn = sqn;
		ret = limit_ota_endDevice_request_speed(&otaBlockDelay);
#endif
		if (ret == 0) 
		{
			send_ota_block_response(&blockMsg);
		}
	}
	break;

	case E_SL_MSG_UPGRADE_END_REQUEST:
	{
		uint8 offset = 0;

		offset += 5;
		uint16 u16SrcAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint32 u32FileVersion = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
		uint16 u16ImageType = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint16 u16ManufactureCode = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint8 u8Status = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);

		reset_limit_ota_device(u16SrcAddr);
		_DBG("[OTA SUCCESSFUL]: saddr:0x%x, fver:%d, image:0x%x, manuc:0x%x, status:%d\n"
			,u16SrcAddr, u32FileVersion, u16ImageType, u16ManufactureCode, u8Status
		);
	}
	break;

	case E_SL_MSG_NEXT_IMAGE_REQUEST:
	{
		uint8 offset = 0;

		offset += 5;
		uint16 u16SrcAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint32 u32FileVersion = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
		uint16 u16ImageType = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint16 u16ManufactureCode = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		uint8 u8FieldControl = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);

		_DBG("Get OTA NEXT IMAGE REQUEST:\n"
			"saddr:0x%x, filever:0x%x, imgType:0x%x, manucode:0x%x, fcontrol:0x%x\n"
			,u16SrcAddr,u32FileVersion,u16ImageType,u16ManufactureCode,u8FieldControl
		);
	}
	break;

	case E_SL_MSG_VIEW_GROUP_RESPONSE:
	{
		uint8 offset = 0;
		
        offset += 4;
        getDeviceGroupExistStatus = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
		ZG_DEBUG("Response view group status: %d\n", getDeviceGroupExistStatus);
		if (getDeviceGroupExistStatus != 0)
        {
            getDeviceGroupExistStatus = -1;   // not exist group number from this device
        }
	}
	break;

    case E_SL_MSG_STATUS:
    {
        openNetworkStatus = 1;   // mark start network successful.
        if (s_initDeviceStatus == E_INIT_ELECTRICAL_MEASUREMENT_REPORT_CONFIG_REQ)
        {
            sendHost2NodeMsg(E_SL_MSG_BIND,pu8MsgBuf,u16MsgLen);
        }
    }
    break;

    case E_SL_MSG_MANAGEMENT_LQI_RESPONSE:
    {
        uint8 offset = 0;

        offset += 24;
        lqiResponseDeviceStatus = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
    }
    break;

    case E_SL_MSG_REMOVE_GROUP_RESPONSE:
    {
        uint8 offset = 0;
        uint8 ctlStatus = 0;

        offset += 4;
        ctlStatus = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        ZG_DEBUG("RSP: delete group status: 0x%x\n", ctlStatus);
        if (ctlStatus == 0 || ctlStatus == 0x8B)
        {
            taskDoneStatus = 1;   // update add group status
        }
    }
    break;

    case E_SL_MSG_ADD_GROUP_RESPONSE:
    {
        uint8 offset = 0;
        uint16 u16addStatus = 0;

        offset += 4;
        u16addStatus = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        ZG_DEBUG("RSP: add group status: 0x%x\n", u16addStatus);

        if (u16addStatus == 0 || u16addStatus == 0x8A)
        {
            taskDoneStatus = 1;   // update add group status
        }
    }
    break;

    case E_SL_MSG_NETWORK_JOINED_FORMED:
    {
        uint8 offset = 0;
        uint8 _status;  // 0 = joined existing network,  1 = Formed new network, 128 - 244 = Failed
        uint16 _sAddr;
        uint64 _extendAddr;
        uint8 _channel;

        _status = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        _sAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        _extendAddr = ZNC_RTN_U64_OFFSET(pu8MsgBuf, offset, offset);
        _channel = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        ZG_DEBUG("Networkstatus:%d, short Addr:0x%x, extend Addr:0x%l, channel:%d\n",
               _status, _sAddr, _extendAddr, _channel);

        openNetworkStatus = 1;   // mark start network successful.
    }
    break;

    case E_SL_MSG_VERSION_LIST:
    {
        uint8 offset = 0;
        uint16 majorVersion = 0;
        uint16 installerVersion = 0;

        majorVersion = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        installerVersion = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        oldMajorVersion = majorVersion;
        sql_update_majorVersion(majorVersion, 1);
        ZG_DEBUG("majorVersion:%d, installerVersion:%d\n", majorVersion, installerVersion);
    }
    break;

    case E_SL_MSG_IEEE_ADDRESS_RESPONSE:
    {
        uint8 offset = 2;
        if (s_jn5169MacL == 0)
        {
        s_jn5169MacH = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
        s_jn5169MacL = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
        ZG_INFO("s_jn5169MacH = =%08X, s_jn5169MacL = %08X\n", s_jn5169MacH, s_jn5169MacL);
    }
    }
    break;

    case E_SL_MSG_DEVICE_ANNOUNCE:
    {
        uint8 offset = 0;
        uint16 u16MsgNwkAddr = 0;
        uint32 u32MsgIEEEAddrH = 0, u32MsgIEEEAddrL = 0;
        char macAddr[64] = "\0";
        //uint8 u8DeviceCapability;

        u16MsgNwkAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        u32MsgIEEEAddrH = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
        u32MsgIEEEAddrL = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);

        memset(macAddr, '\0', 64);
        sprintf(macAddr, "%d%d", u32MsgIEEEAddrH, u32MsgIEEEAddrL);

        ZG_INFO("Announce IEEEAddrH=%08X IEEEAddrL=%08X NwkAddr=%04X MACAddr=%s\n",
                u32MsgIEEEAddrH, u32MsgIEEEAddrL, u16MsgNwkAddr, macAddr);
        //u8DeviceCapability = pu8MsgBuf[10];
        //if((u8DeviceCapability&0x02) != 0) //router device, available for demo 121
        {
            memset(&device, '\0', sizeof(zgw_device_t));
            strcat(device.name, "unkown");
            strcpy(device.mact, macAddr);
            device.tag = 0xFFFF;
            device.sta = 0xFF;
            device.addr = u16MsgNwkAddr;
            device.mach = u32MsgIEEEAddrH;
            device.macl = u32MsgIEEEAddrL;
            sql_insert_device(&device);
        }
        sendHost2NodeMsg(E_SL_MSG_ACTIVE_ENDPOINT_REQUEST,pu8MsgBuf,u16MsgLen);

		if (s_initDeviceStatus == E_INIT_FINISH)
		{
			s_need_init_device_flag = 1;
			s_initDeviceStatus = E_INIT_WAIT;    // WHEN RECEVIE DEVICE ANOUNCE, OPEN CHECK INIT DEVICE
		}
    }
    break;

    case E_SL_MSG_ACTIVE_ENDPOINT_RESPONSE:
    {
        uint8 offset = 0;
        uint16 u16MsgNwkAddr = 0;
        uint8 u8MsgEndpoint = 0;

        offset += 2;
        u16MsgNwkAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        offset += 1;
        u8MsgEndpoint = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);

        ZG_INFO("Active endpoint NwkAddr=%04X endpoint=%d\n", u16MsgNwkAddr, u8MsgEndpoint);
        sendHost2NodeMsg(E_SL_MSG_SIMPLE_DESCRIPTOR_REQUEST,pu8MsgBuf,u16MsgLen);
    }
    break;

    case E_SL_MSG_SIMPLE_DESCRIPTOR_RESPONSE:
    {
#define ZLL_PROFILEID  (0xC05E)
        uint8 offset = 0;
        uint16 u16MsgNwkAddr = 0;
        uint8 u8MsgEndpoint = 0;
        uint16 u16MsgProfileId = 0;
        uint16 u16MsgDeviceId = 0;

        offset += 2;
        u16MsgNwkAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        offset += 1;
        u8MsgEndpoint = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        u16MsgProfileId = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        u16MsgDeviceId = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);

        ZG_INFO("Simple descriptor NwkAddr=%04X EP=%d Profile=%d DeviceId=%d\n",
                u16MsgNwkAddr, u8MsgEndpoint, u16MsgProfileId, u16MsgDeviceId);

        if (u16MsgProfileId == ZLL_PROFILEID)
        {
            if (u16MsgDeviceId == E_ZHA_ONF_SWITCH_PROFILE_ID)
            {
                u16MsgDeviceId = E_ZLL_ONF_LIGHT_PROFILE_ID;
            }
            else if(u16MsgDeviceId == E_ZHA_LEVEL_CONTROL_SWITCH_PROFILE_ID)
            {
                u16MsgDeviceId = E_ZLL_ONF_PLUGIN_PROFILE_ID;
            }
            else if (u16MsgDeviceId == E_ZHA_ONF_LIGHT_PROFILE_ID)
            {
                u16MsgDeviceId = E_ZLL_DIMMABLE_LIGHT_PROFILE_ID;
            }
            else
            {
                //do nothing
            }
        }

        do
        {
            //update record in db
            tsDeviceWebdef temp;
            memset(&device, '\0', sizeof(zgw_device_t));
            device.name[0] = '\0';
            device.tag = u16MsgDeviceId;
            device.sta = 0xFF;
            device.addr = u16MsgNwkAddr;

            getDeviceWebdef(u16MsgDeviceId,&temp);
            device.tag = temp.tag;
            strncpy(device.name, temp.name, 128);

            sql_update_device(&device);
        }
        while(0);
    }
    break;

    case E_SL_MSG_POWER_DESCRIPTOR_RESPONSE:
        break;

    case E_SL_MSG_MEASUREMENT_ELECTRIC_USE_HOUR_RSP:
    {
        uint8 offset = 0;
        uint16 u16MsgNwkAddr = 0;
        uint16 u16MsgOnhour = 0, u16MsgOffhour = 0;

        u16MsgNwkAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        u16MsgOnhour = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        u16MsgOffhour = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);

        ZG_INFO("descriptor 0x8A05 NwkAddr=%04X onhour=%d offhour=%d\n", u16MsgNwkAddr, u16MsgOnhour, u16MsgOffhour);
        sql_update_device_lifetime(u16MsgNwkAddr,u16MsgOnhour,u16MsgOffhour);
    }
    break;

    case E_SL_MSG_MEASUREMENT_ELECTRIC_USE_ENERGE_RSP:
    {
        uint8 offset = 0;
        uint16 u16MsgNwkAddr = 0;
        uint32 u32MsgTotalUseEnergyH = 0, u32MsgTotalUseEnergyL = 0;
        uint16 u16watt = 0;

        u16MsgNwkAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        u32MsgTotalUseEnergyH = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
        u32MsgTotalUseEnergyL = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
        u16watt = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);

        ZG_INFO("descriptor 0x8A06 NwkAddr=%04X TotalUseEnergyH=%d TotalUseEnergyL=%d u16watt = %d\n",
                u16MsgNwkAddr, u32MsgTotalUseEnergyH, u32MsgTotalUseEnergyL, u16watt);
        sql_update_device_energy(u16MsgNwkAddr,u32MsgTotalUseEnergyH, u32MsgTotalUseEnergyL);
        sql_update_device_watt(u16MsgNwkAddr, u16watt);
        _setDeviceFlag(u16MsgNwkAddr);
    }
    break;

	case E_SL_MSG_READ_ATTRIBUTE_RESPONSE:	/* 0x8100 */
    case E_SL_MSG_WRITE_ATTRIBUTE_RESPONSE:
    case E_SL_MSG_REPORT_IND_ATTR_RESPONSE:
    {
        uint8 offset = 0;
        uint16 u16MsgNwkAddr = 0;
        uint8 u8MsgEndpoint = 0;
        uint16 u16MsgClusterID = 0;
        uint16 u16MsgAttributeID = 0;
		uint8 u8AttributeStauts = 0;

        offset += 1;
        u16MsgNwkAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        u8MsgEndpoint = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        u16MsgClusterID = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        u16MsgAttributeID = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
		u8AttributeStauts = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        //offset += ((u16MsgType == E_SL_MSG_REPORT_IND_ATTR_RESPONSE) ? (3) : (4));
        offset += 3;

        ZG_INFO("descriptor(0x%x) NwkAddr=%04X EP=%d ClusterID=%x AttributeID=%x status=%x\n",
                u16MsgType, u16MsgNwkAddr, u8MsgEndpoint, u16MsgClusterID, u16MsgAttributeID, u8AttributeStauts);

		if (u16MsgType == E_SL_MSG_WRITE_ATTRIBUTE_RESPONSE)
		{
			if (u16MsgClusterID == ELECTRICAL_MEASUREMENT_CLUSTER_ID 
				&& u8AttributeStauts == 0)
			{
				uint32 u32PlugAlarmValue = 0;

				s_setPlugAlarmStatus = 1; /* set plug alarm value successful flag */
				u32PlugAlarmValue = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
				ZG_INFO("set plug alarm value: %d\n", u16MsgNwkAddr);
			}
		}

		/* response read EndDevice current version */
	    if (u16MsgClusterID == 0 && u16MsgAttributeID == 1 && u8AttributeStauts == 0)
    	{
    		tmpEndDeviceVersion = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
		}

        switch(u16MsgClusterID)
        {
        case ELECTRICAL_MEASUREMENT_CLUSTER_ID:
        {
            if (u16MsgAttributeID == ACTIVE_POWER_ATTRIBUTE_ID)
            {
                uint16 u16watt = 0;
				uint16 u16deviceTag = 0;
				uint16 u16deviceRatedwatt = 0;

                u16watt = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
                ZG_INFO("u16watt = %d\n", u16watt);
				
				/* 1.get tag and rated watt */
				if (sql_get_device_tag_and_rated_watt(u16MsgNwkAddr, &u16deviceTag, &u16deviceRatedwatt) == 0)
				{
					/* 2.if watt > alarm value, set alarm flag on db */
					if (u16deviceTag == 65 && (u16watt > u16deviceRatedwatt * s_plugAlarmValue / 100))
					{
						_DBG("Have plug alarm , greate than alarm value: %d\n", u16deviceRatedwatt * s_plugAlarmValue / 100);
						sql_set_plug_alarm_flag(u16MsgNwkAddr);
					}
				}

                sql_update_device_watt(u16MsgNwkAddr, u16watt);
                _setDeviceFlag(u16MsgNwkAddr);
            }
            else if (u16MsgAttributeID == MAN_SPEC_DIVISOR_ATTRIBUTE_ID)
                    {
                uint16 u16onhour = 0;

                u16onhour = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
                ZG_INFO("u16onhour = %d\n", u16onhour);
                sql_update_device_lifetime(u16MsgNwkAddr,u16onhour, 0);
            }
			else if (u16MsgAttributeID == PLUG_REAED_WATT_ATTRIBUTE_ID)
			{
				uint16 u16PlugRatedWatt = 0;

				u16PlugRatedWatt = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
                ZG_INFO("u16PlugRatedWatt = %d\n", u16PlugRatedWatt);
				sql_update_plug_ratedwatt(u16MsgNwkAddr, u16PlugRatedWatt);
			}
			#if 1
			else if (u16MsgAttributeID == PLUG_ALARM_WATT_ATTRIBUTE_ID)
			{
				uint32 u32PlugAlarmValue = 0;
				
				u32PlugAlarmValue = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
				ZG_INFO("Read plug set alarm value: 0x%x\n", u32PlugAlarmValue);
			}
			#endif
        }
        break;
        case METERING_CLUSTER_ID:
        {
            if (u16MsgAttributeID == CURRENT_SUMMATION_ATTRIBUTE_ID)
            {
                uint32 u32MsgTotalUseEnergyH = 0, u32MsgTotalUseEnergyL = 0;

                u32MsgTotalUseEnergyH = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
                u32MsgTotalUseEnergyL = ZNC_RTN_U32_OFFSET(pu8MsgBuf, offset, offset);
                ZG_INFO("u32MsgTotalUseEnergyH = %d, u32MsgTotalUseEnergyL = %d\n", u32MsgTotalUseEnergyH, u32MsgTotalUseEnergyL);
                sql_update_device_energy(u16MsgNwkAddr,u32MsgTotalUseEnergyH, u32MsgTotalUseEnergyL);
            }
        }
        break;
        case ONOFF_CLUSTER_ID:
        {
            if (u16MsgAttributeID == ONOFF_ATTRIBUTE_ID)
            {
                uint8 u8MsgOnf = 0;

                u8MsgOnf = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
                ZG_INFO("u8MsgOnf = %d\n", u8MsgOnf);
                sql_update_device_onoff(u16MsgNwkAddr, u8MsgOnf);
            }
        }
        break;
        case LEVEL_CONTROL_CLUSTER_ID:
        {
            if (u16MsgAttributeID == CURRENT_LEVEL_ATTRIBUTE_ID)
            {
                uint8 u8MsgLevel = 0;

                u8MsgLevel = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
                ZG_INFO("u8MsgLevel = %d\n", u8MsgLevel);
                sql_update_device_lum(u16MsgNwkAddr, u8MsgLevel);
            }
        }
        break;
        case COLOR_CONTROL_CLUSTER_ID:
        {
            if (u16MsgAttributeID == CURRENT_HUE_ATTRIBUTE_ID)
            {
                uint8 u8MsgHue = 0;

                u8MsgHue = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
                ZG_INFO("u8MsgHue = %d\n", u8MsgHue);
                sql_update_device_hue(u16MsgNwkAddr, u8MsgHue);
            }
            else if (u16MsgAttributeID == COLOR_TEMPERATURE_MIREDS_ATTRIBUTE_ID)
            {
                /*cct={153..370}<-{1..218}*/
                uint16 u16MsgCct = 0;

                u16MsgCct = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);

                u16MsgCct = (u16MsgCct > 370)?(370):(u16MsgCct);
                u16MsgCct = (u16MsgCct < 153)?(153):(u16MsgCct);
                u16MsgCct -= 152;
                u16MsgCct = 218 - u16MsgCct + 1;  //see sendHost2NodeMsg() how to set cct value

                ZG_INFO("u16MsgCct = %d\n", u16MsgCct);
                sql_update_device_ct(u16MsgNwkAddr, u16MsgCct);
            }
            else
            {
                //do nothing
            }
        }
        break;

        default:
            break;
        }
    }
    break;

    case E_SL_MSG_CONFIG_REPORTING_RESPONSE:
    {
        uint8 offset = 0;
        uint16 u16MsgNwkAddr, u16MsgClusterID;
        uint8 u8MsgEndpoint, u8Status;
    
        offset += 1;
        u16MsgNwkAddr = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        u8MsgEndpoint = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
        u16MsgClusterID = ZNC_RTN_U16_OFFSET(pu8MsgBuf, offset, offset);
        u8Status = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
    
        ZG_DBG(">> E_SL_MSG_CONFIG_REPORTING_RESPONSE\n");
        sendHost2NodeMsg(E_SL_MSG_BIND,pu8MsgBuf,u16MsgLen);
    }
    break;
    
    case E_SL_MSG_BIND_RESPONSE:
    {
        uint8 offset = 0;
        uint8 u8Status = 0;
    
        offset += 1;
        u8Status = ZNC_RTN_U8_OFFSET(pu8MsgBuf, offset, offset);
    
        switch (s_initDeviceStatus)
        {
        case E_INIT_ONOFF_BIND_REQ:
            if (s_initDeviceTag == 61)
            {
                sql_update_device_ott(s_initDeviceAddr, 1);  // onoff light init finished
                _DBG("ONF device init finished. saddr: %d\n", s_initDeviceAddr);
                s_initDeviceStatus = E_INIT_WAIT;
                return E_MSG_EVENT_FINISH;
            }
            break;
        case E_INIT_LEVEL_BIND_REQ:
            if (s_initDeviceTag == 62)
            {
                sql_update_device_ott(s_initDeviceAddr, 1);  // dim light init finished
                _DBG("LUM device init finished. saddr: %d\n", s_initDeviceAddr);
                s_initDeviceStatus = E_INIT_FINISH;
                //sendHost2NodeMsg(E_SL_MSG_MOVE_TO_LEVEL_ONOFF, pu8MsgBuf,u16MsgLen);
                lua_set_device_lum(E_SL_MSG_MOVE_TO_LEVEL_ONOFF, s_initDeviceAddr, 127);
                return E_MSG_EVENT_FINISH;
            }
            break;
        case E_INIT_COLOR_BIND_REQ:
            if (s_initDeviceTag == 63)
            {
                sql_update_device_ott(s_initDeviceAddr, 1);  // cct light init finished
                _DBG("CCT device init finished. saddr: %d\n", s_initDeviceAddr);
                s_initDeviceStatus = E_INIT_FINISH;
               // sendHost2NodeMsg(E_SL_MSG_MOVE_TO_COLOUR_TEMPERATURE, pu8MsgBuf,u16MsgLen);
               lua_set_device_cct(E_SL_MSG_MOVE_TO_COLOUR_TEMPERATURE, s_initDeviceAddr, 285);
                return E_MSG_EVENT_FINISH;
            }
            else if (s_initDeviceTag == 64)
            {
                sql_update_device_ott(s_initDeviceAddr, 1);  // rgb light init finished
                _DBG("RGB device init finished. saddr: %d\n", s_initDeviceAddr);
                s_initDeviceStatus = E_INIT_FINISH;
                //sendHost2NodeMsg(E_SL_MSG_ENHANCED_MOVE_TO_HUE_SATURATION, pu8MsgBuf,u16MsgLen);
				lua_set_device_hue(E_SL_MSG_ENHANCED_MOVE_TO_HUE_SATURATION, s_initDeviceAddr, 1);
                return E_MSG_EVENT_FINISH;
            }
            break;
        case E_INIT_ELECTRICAL_MEASUREMENT_BIND_REQ:
            if (s_initDeviceTag == 65)
            {
                sql_update_device_ott(s_initDeviceAddr, 1);  // smart plug init finished
                _DBG("Smart plug init finished. saddr: %d\n", s_initDeviceAddr);
                s_initDeviceStatus = E_INIT_WAIT;

				/* send msg to read plug rated watt */
				lua_get_plug_rated_watt(s_initDeviceAddr);

				return E_MSG_EVENT_FINISH;
            }
            break;
        default:
            break;
        }
        sendHost2NodeMsg(E_SL_MSG_CONFIG_REPORTING_REQUEST,pu8MsgBuf,u16MsgLen);
    }
    break;

    default:
        return E_MSG_EVENT_NOT_FIND;
        break;
    }

    return E_MSG_EVENT_FINISH;
}


static void processData(void)
{
    tsMsgQueueNode tsMsgNodeData = {0};
    long int msgNodeType = 0;

    while(1)
    {
        if(msgrcv(node2host_msgid, (void*)&tsMsgNodeData, sizeof(tsMsgQueueNode), msgNodeType, 0) == -1)
        {
            //ZG_DBG("processData: msgrcv fail\n");
            continue;
        }
        //ZG_DBG("Host <- Node: data, date_len = {0x%02x, %d} \n", tsMsgNodeData.data[2], tsMsgNodeData.data_len);
        //analyseData(tsMsgNodeData.data, tsMsgNodeData.data_len);
        memset(&s_tsMsgCircleBuffer[s_cbufferIndexWrite], 0, sizeof(tsMsgQueueNode));
        memcpy(&s_tsMsgCircleBuffer[s_cbufferIndexWrite], &tsMsgNodeData, sizeof(tsDeviceWebdef));
        s_cbufferIndexWrite++;
        s_cbufferIndexWrite = (s_cbufferIndexWrite == MAX_CBUFFER_LENTH) ? (0) : (s_cbufferIndexWrite);
    }
}

void progressCheckout_init_struct_memory(dbGroupTaskParameter* groupTaskParameter, int* initFlag)
{
	*initFlag = 0;
	APPLY_MEMORY_AND_CHECK(groupTaskParameter->p_taskId,GROUP_TASK_ID)
	APPLY_MEMORY_AND_CHECK(groupTaskParameter->p_deviceList,DEVICE_LIST_MAX)
	APPLY_MEMORY_AND_CHECK(groupTaskParameter->p_successDeviceList,DEVICE_LIST_MAX)
	APPLY_MEMORY_AND_CHECK(groupTaskParameter->p_successDeleteDeviceList,DEVICE_LIST_MAX)
	APPLY_MEMORY_AND_CHECK(groupTaskParameter->p_errDeviceList,DEVICE_LIST_MAX)
	*initFlag = 1;
}

static void processCheckout(void)
{
	ZG_ENTER();
    static dbGroupTaskParameter groupTaskParameter;
	int initStructFlag = 0;
		
	progressCheckout_init_struct_memory(&groupTaskParameter, &initStructFlag);
	if (initStructFlag == 0)
	{
		_DBG("[!!! exit]init processCheckout struct error.\n");
		exit(0);  // init processCheckout struct error
	}
    sleep(30);

    ZG_DEBUG("Task process checkout work.\n");
    while (1)
    {
        memset(groupTaskParameter.p_taskId, '\0', GROUP_TASK_ID);
        memset(groupTaskParameter.p_deviceList, '\0', DEVICE_LIST_MAX);
        if (sql_get_db_grouptask(&groupTaskParameter) == 0)
        {
            grouptask_handler(&groupTaskParameter);
            ZG_DEBUG("%s %d\n", __FUNCTION__, __LINE__);
        }
		
        sleep(5);
    }
}

static int addGroup_task(dbGroupTaskParameter* groupTaskParameter)
{
    uint16 addr = 0;
    uint16 gid = groupTaskParameter->groupId;
    uint8 u8MsgBuf[4] = {0};
    uint32 u32MsgLen = 0;
    uint8 i = 0, sendTime = 0;
    uint8 deviceCount = 0, addGroupSuccessfulCount = 0;
    char delims[] = ",";
    char *getDevAddr = NULL;
    char* DevAddrBuf = NULL;
    char deviceAddr[32] = "\0";
    char sql[SQL_BUF_MAX] = "\0";
    int notUse = 0;
    uint16 devAddrIndex = 0;
    char* p_getDevAddr[512] = {NULL};

    DevAddrBuf = (char*)malloc(DEVICE_LIST_MAX);
    if (DevAddrBuf == NULL)
    {
        ZG_DEBUG("Error: malloc memory line: %d.\n", __LINE__);
        groupTaskParameter->taskStatus = T_HANDLER_ERROR;
        return 0;
    }
    m_strncpy(DevAddrBuf,groupTaskParameter->p_deviceList, DEVICE_LIST_MAX);

    _DBG("In %s, add list:%s\n", __FUNCTION__, DevAddrBuf);
    getDevAddr = strtok(DevAddrBuf, delims);
    devAddrIndex = 0;
    p_getDevAddr[devAddrIndex] = NULL;
    while (getDevAddr != NULL)
    {
        p_getDevAddr[devAddrIndex] = getDevAddr;
        p_getDevAddr[++devAddrIndex] = NULL;
        getDevAddr = strtok( NULL, delims );  // get next device address
    }

#if 1
    devAddrIndex = 0;
    while (p_getDevAddr[devAddrIndex] != NULL)
    {
        _DBG("[%d]	%s\n", devAddrIndex, p_getDevAddr[devAddrIndex]);
        devAddrIndex++;
    }
#endif


    // 1. loop send addGroup request
    devAddrIndex = 0;
    while (p_getDevAddr[devAddrIndex] != NULL)
    {
        u32MsgLen = 0;
        memset(u8MsgBuf, '\0', sizeof(u8MsgBuf));

#define ADD_GROUP_USE_MAC_LIST
//#define ADD_GROUP_USE_SHORT_ADDRESS_LIST
#ifdef ADD_GROUP_USE_MAC_LIST
        // get short addr by mac from DB
        memset(deviceAddr, '\0', 32);
        memset(sql, '\0', SQL_BUF_MAX);
        snprintf(sql, SQL_BUF_MAX, "select id,addr from devices where mact = '%s';", p_getDevAddr[devAddrIndex]);
        sql_get_ont_item(sql, GET_STRING, &notUse, deviceAddr);

        addr = (uint16)atoi(deviceAddr);  // string address change integer
        ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], addr, u32MsgLen);
        ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], gid, u32MsgLen);

        memset(deviceAddr, '\0', 32);
        m_strncpy(deviceAddr, p_getDevAddr[devAddrIndex], 32);

#else ifdef ADD_GROUP_USE_SHORT_ADDRESS_LIST
        addr = (uint16)atoi(p_getDevAddr[devAddrIndex]);  // string address change integer
        ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], addr, u32MsgLen);
        ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], gid, u32MsgLen);
        memset(deviceAddr, '\0', 32);
        sprintf(deviceAddr, "%d", addr);
#endif

        //handler next device when successful, handler one and the same when error, but total try 3 times
        for (i=0; i<3; i++)
        {
            taskDoneStatus = 0;

            ZG_DEBUG("\n[ADD] addr: %s groupId:%d, try %d times.\n", p_getDevAddr[devAddrIndex], gid, i+1);
            sendHost2NodeMsg(E_SL_MSG_ADD_GROUP,u8MsgBuf,4);
            sendTime = 2 * i + 5;
            sleep(sendTime);

            if (taskDoneStatus)
            {
                addGroupSuccessfulCount++;
                ZG_DEBUG("\nSuccessful, dev:%d, add group:%d. total try: %d times.\n", addr, gid, i+1);
                if (sql_add_group_mark_to_devices(gid, p_getDevAddr[devAddrIndex]) == -1)
                {
                    _DBG("[Error] Update devices addgl.\n");
                }

                strcat(groupTaskParameter->p_successDeviceList, ",");
                strcat(groupTaskParameter->p_successDeviceList, deviceAddr);
                break;  // add group successful, and then  to add next device
            }

            if (i == 2)  // some device add group error
            {
                strcat(groupTaskParameter->p_errDeviceList, ",");
                strcat(groupTaskParameter->p_errDeviceList, deviceAddr);
            }
        }

        deviceCount++;
        devAddrIndex++;
    }

    // 2. get response data, and then analysis control status
    // 3.update task status
    free(DevAddrBuf);
    DevAddrBuf = NULL;
    if (deviceCount == addGroupSuccessfulCount)
    {
        ZG_DEBUG("p_deviceList: %s\n", groupTaskParameter->p_deviceList);
        groupTaskParameter->taskStatus = T_HANDLER_SUCCESSFUL;
        ZG_DEBUG("Successful add group: %d\n", groupTaskParameter->groupId);
        return 1;
    }
    else
    {
        groupTaskParameter->taskStatus = T_HANDLER_ERROR;
        ZG_DEBUG("Error add group: %d\n", groupTaskParameter->groupId);
        return 2;
    }
}

static void analysis_update_group_device(const char* sDev, const char* dDev,char* addDev,char* delDev, int groupNum)
{
    char srcDeviceList[DEVICE_LIST_MAX] = "\0";
    char dstDeviceList[DEVICE_LIST_MAX] = "\0";
    char* p_srcDeviceList[256] = {NULL};
    char* p_dstDeviceList[256] = {NULL};
    char delims[] = ",";
    uint8 i = 0, j = 0;
    uint8 existStatus = 0;
    //uint8 index = 0;
    uint8 srcDeviceListLength = 0, dstDeviceListLength = 0;

    memset(srcDeviceList, '\0', DEVICE_LIST_MAX);
    memset(dstDeviceList, '\0', DEVICE_LIST_MAX);
    m_strncpy(srcDeviceList, sDev, DEVICE_LIST_MAX);
    m_strncpy(dstDeviceList, dDev, DEVICE_LIST_MAX);

    ZG_DEBUG("\n src device list:");
    j = 0;
    p_srcDeviceList[j] = strtok(srcDeviceList, delims);
    while (p_srcDeviceList[j] != NULL)
    {
        printf("%s ", p_srcDeviceList[j]);
        srcDeviceListLength++;
        p_srcDeviceList[++j] = strtok(NULL, delims);
    }

    ZG_DEBUG("\n dst device list:");
    j = 0;
    p_dstDeviceList[j] = strtok(dstDeviceList, delims);
    while (p_dstDeviceList[j] != NULL)
    {
        printf("%s ", p_dstDeviceList[j]);
        dstDeviceListLength++;
        p_dstDeviceList[++j] = strtok(NULL, delims);
    }

    for ( i = 0; i < srcDeviceListLength; i++)
    {
        existStatus = 0;
        for ( j = 0; j < dstDeviceListLength; j++)
        {
            if (strcmp(p_srcDeviceList[i], p_dstDeviceList[j]) == 0)
            {
                existStatus = 1;   // device do not need to delete
                break;
            }
        }

        if (existStatus == 0)
        {
            strcat(delDev, ",");
            strcat(delDev, p_srcDeviceList[i]);
        }
    }
    ZG_DEBUG("\n del device list: %s", delDev);

	if (groupNum == -1)
	{
		for ( i = 0; i < dstDeviceListLength; i++)
	    {
	        existStatus = 0;
	        for ( j = 0; j < srcDeviceListLength; j++)
	        {
	            if (strcmp(p_dstDeviceList[i], p_srcDeviceList[j]) == 0)
	            {
	                existStatus = 1;   // device do not need to add
	                break;
	            }
	        }

	        if (existStatus == 0)
	        {
	            strcat(addDev, ",");
	            strcat(addDev, p_dstDeviceList[i]);
	        }
	    }
	}
	else
	{
		for ( i = 0; i < dstDeviceListLength; i++)
	    {
	        existStatus = 0;
	        for ( j = 0; j < srcDeviceListLength; j++)
	        {
	            if (strcmp(p_dstDeviceList[i], p_srcDeviceList[j]) == 0
					&& sql_check_device_join_group_status(groupNum, p_dstDeviceList[i]) == 0)
	            {
	                existStatus = 1;   // device do not need to add
	                break;
	            }
	        }

	        if (existStatus == 0)
	        {
	            strcat(addDev, ",");
	            strcat(addDev, p_dstDeviceList[i]);
	        }
	    }
	}
    
    ZG_DEBUG("\n add device list: %s", addDev);

    return;
}

static int deleteGroup_task(dbGroupTaskParameter* groupTaskParameter)
{
    char* deviceList = NULL;
    uint8 deviceCount = 0, addGroupSuccessfulCount = 0;
    char delims[] = ",";
    char *getDevAddr = NULL;
    uint32 u32MsgLen = 0;
    uint8 u8MsgBuf[4] = {0};
    uint16 addr = 0;
    uint16 gid = groupTaskParameter->groupId;
    uint32 i, sendTime = 0;
    char deviceAddr[32] = "\0";
    char* sql = NULL;
    int notUse;
    char* p_getDevAddr[512] = {NULL};
    uint16 devAddrIndex = 0;

	APPLY_MEMORY_AND_CHECK(deviceList,DEVICE_LIST_MAX)
	APPLY_MEMORY_AND_CHECK(sql,SQL_BUF_MAX)
    // 1. get group device list on DB  and update grouptask status
    memset(deviceList, '\0', DEVICE_LIST_MAX);
    m_strncpy(deviceList, groupTaskParameter->p_deviceList, DEVICE_LIST_MAX);

    _DBG("In %s, delete list:%s\n", __FUNCTION__, deviceList);
    getDevAddr = strtok(deviceList, delims);
    devAddrIndex = 0;
    p_getDevAddr[devAddrIndex] = NULL;
    while (getDevAddr != NULL)
    {
        p_getDevAddr[devAddrIndex] = getDevAddr;
        p_getDevAddr[++devAddrIndex] = NULL;
        getDevAddr = strtok( NULL, delims );  // get next device address
    }

#if 1
    devAddrIndex = 0;
    while (p_getDevAddr[devAddrIndex] != NULL)
    {
        _DBG("[%d]  %s\n", devAddrIndex, p_getDevAddr[devAddrIndex]);
        devAddrIndex++;
    }
#endif


    devAddrIndex = 0;
    while (p_getDevAddr[devAddrIndex] != NULL)
    {
        u32MsgLen = 0;
        memset(u8MsgBuf, '\0', sizeof(u8MsgBuf));

#define ADD_GROUP_USE_MAC_LIST
//#define ADD_GROUP_USE_SHORT_ADDRESS_LIST
#ifdef ADD_GROUP_USE_MAC_LIST
        // get short addr by mac from DB
        memset(deviceAddr, '\0', 32);
        memset(sql, '\0', SQL_BUF_MAX);
        snprintf(sql, SQL_BUF_MAX, "select id,addr from devices where mact = '%s';", p_getDevAddr[devAddrIndex]);
        sql_get_ont_item(sql, GET_STRING, &notUse, deviceAddr);

        addr = (uint16)atoi(deviceAddr);  // string address change integer
        ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], addr, u32MsgLen);
        ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], gid, u32MsgLen);

        memset(deviceAddr, '\0', 32);
        m_strncpy(deviceAddr, p_getDevAddr[devAddrIndex], 32);

#else ifdef ADD_GROUP_USE_SHORT_ADDRESS_LIST
        addr = (uint16)atoi(p_getDevAddr[devAddrIndex]);  // string address change integer
        ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], addr, u32MsgLen);
        ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], gid, u32MsgLen);
        memset(deviceAddr, '\0', 32);
        sprintf(deviceAddr, "%d", addr);
#endif

        //2. handler next device when successful, handler one and the same when error, but total try 3 times
        for (i=0; i<3; i++)
        {
            taskDoneStatus = 0;

            ZG_DEBUG("\n[DELETE] addr: %s groupId:%d, try %d times.\n", p_getDevAddr[devAddrIndex], gid, i+1);
            sendHost2NodeMsg(E_SL_MSG_REMOVE_GROUP,u8MsgBuf,4);
            sendTime = 2 * i + 5;
            sleep(sendTime);

            if (1)
            {
                addGroupSuccessfulCount++;
                ZG_DEBUG("\nSuccessful, dev:%d, delete group:%d. total try: %d times.\n", addr, gid, i+1);

                if (sql_delete_group_mark_to_devices(gid, p_getDevAddr[devAddrIndex]) != 0)
                {
                    _DBG("[Error] Update devices addgl.\n");
                }

                strcat(groupTaskParameter->p_successDeleteDeviceList, ",");
                strcat(groupTaskParameter->p_successDeleteDeviceList, deviceAddr);

                break;  // delete group successful, and then  to delete next device
            }

            if (i == 2)  // some device add group error
            {
                strcat(groupTaskParameter->p_errDeviceList, ",");
                strcat(groupTaskParameter->p_errDeviceList, deviceAddr);
            }
        }

        deviceCount++;
        devAddrIndex++;
    }

	FREE_APPLY_MEMORY(deviceList)
	FREE_APPLY_MEMORY(sql)

    // 3. delete group on DB
    if (deviceCount == addGroupSuccessfulCount)
    {
        groupTaskParameter->taskStatus = T_HANDLER_SUCCESSFUL;
        ZG_DEBUG("Successful delete group: %d\n", groupTaskParameter->groupId);
        return 1;
    }
    else
    {
        ZG_DEBUG("Delete group task error.\n");
        groupTaskParameter->taskStatus = T_HANDLER_ERROR;
        return 2;
    }
}

static int updateGroup_task(dbGroupTaskParameter* groupTaskParameter)
{
    char srcDeviceList[DEVICE_LIST_MAX] = "\0";
    char dstDeviceList[DEVICE_LIST_MAX] = "\0";
    char addDeviceList[DEVICE_LIST_MAX] = "\0";
    char deleteDeviceList[DEVICE_LIST_MAX] = "\0";
    uint8 addGroupStatus = 0;


    // 1. get group device list on DB, and change task status
    memset(srcDeviceList, '\0', DEVICE_LIST_MAX);
    memset(dstDeviceList, '\0', DEVICE_LIST_MAX);
    sql_get_groups_devlist(srcDeviceList, groupTaskParameter->groupId);
    m_strncpy(dstDeviceList, groupTaskParameter->p_deviceList, DEVICE_LIST_MAX);

    // 2. analysis to add device list and delete device list
    analysis_update_group_device(srcDeviceList, groupTaskParameter->p_deviceList, addDeviceList, deleteDeviceList, groupTaskParameter->groupId);

    // 3. handler add device and delete device
    // add device
    memset(groupTaskParameter->p_deviceList, '\0', DEVICE_LIST_MAX);
    m_strncpy(groupTaskParameter->p_deviceList, addDeviceList, DEVICE_LIST_MAX);
    addGroupStatus = addGroup_task(groupTaskParameter);

    // delete device
    memset(groupTaskParameter->p_deviceList, '\0', DEVICE_LIST_MAX);
    m_strncpy(groupTaskParameter->p_deviceList, deleteDeviceList, DEVICE_LIST_MAX);
    deleteGroup_task(groupTaskParameter);

    // Note: here, if add group error and then delete group successful,  status will successful forever
    if (addGroupStatus == 2)
    {
        groupTaskParameter->taskStatus = T_HANDLER_ERROR;
    }

    //Note: groups save dids:  src device list   - delete successful device list + add successful device list
    memset(addDeviceList, '\0', DEVICE_LIST_MAX);
    memset(deleteDeviceList, '\0', DEVICE_LIST_MAX);
    analysis_update_group_device(srcDeviceList, groupTaskParameter->p_successDeleteDeviceList, addDeviceList, deleteDeviceList, -1);
    strcat(deleteDeviceList, groupTaskParameter->p_successDeviceList);

    memset(groupTaskParameter->p_deviceList, '\0', DEVICE_LIST_MAX);
    m_strncpy(groupTaskParameter->p_deviceList, deleteDeviceList, DEVICE_LIST_MAX);

    return 0;
}


static int get_device_group_recovery(dbGroupTaskParameter* groupTaskParameter, char* sql)
{
    char* p_getGroupArray[256] = {NULL};
    uint8 groupIndex = 0;
    char* mact = groupTaskParameter->p_taskId; // tid is mact
    char delims[] = ",";
    char* p_getGroupNum = NULL;
    uint8 i = 0;
    uint8 addGroupStatus = 0;
    char groupNumList[1024] = "\0";

    memset(groupNumList, '\0', 1024);
    m_strncpy(groupNumList, groupTaskParameter->p_deviceList, 1024);
    _DBG("Recovery group number list: %s\n", groupNumList);
    p_getGroupNum = strtok(groupNumList, delims);
    while (p_getGroupNum != NULL)
    {
        p_getGroupArray[groupIndex++] = p_getGroupNum;
        p_getGroupNum = strtok(NULL, delims);
    }

    for (i = 0; i < groupIndex; i++)
    {
        _DBG("groupNum:[%s]\n", p_getGroupArray[i]);
    }

    for (i = 0; i < groupIndex; i++)
    {
        // add group
        memset(groupTaskParameter->p_deviceList, '\0', DEVICE_LIST_MAX);
        m_strncpy(groupTaskParameter->p_deviceList, mact, DEVICE_LIST_MAX);
        groupTaskParameter->groupId = (uint16)atoi(p_getGroupArray[i]);
        _DBG("[Recovery]: devl:%s, Gid:%d\n", groupTaskParameter->p_deviceList
             , groupTaskParameter->groupId);

        if (addGroup_task(groupTaskParameter) == T_HANDLER_ERROR)
        {
            addGroupStatus = 1;
        }
    }

    if (addGroupStatus == 1)
    {
        groupTaskParameter->taskStatus = T_HANDLER_ERROR;
    }
    else
    {
        groupTaskParameter->taskStatus = T_HANDLER_SUCCESSFUL;
    }

    return 0;
}

int get_device_lqi_status(char* dstDeviceList)
{
    char devList[DEVICE_LIST_MAX] = "\0";
	char sql[SQL_BUF_MAX] = "\0";
    uint16 addr = 0;
    uint8 u8MsgBuf[2] = {0};
    uint32 u32MsgLen = 0;
    //uint8 i = 0;
    char *getDevAddr = NULL;
    char delims[] = ",";
    uint8 getLqiStatus = 0;

    _DBG("Start to get all device LQI status.\n");

    if (dstDeviceList != NULL && strlen(dstDeviceList) > 3)
    {
        memset(devList, '\0', DEVICE_LIST_MAX);
		strncpy(devList, dstDeviceList, DEVICE_LIST_MAX - 1);
        getLqiStatus = 1;
    }
    else
    {
        getLqiStatus = sql_get_alldevice(devList);
    }

    if ( getLqiStatus == 1)
    {
        _DBG("GET ALL DEVICE LIST: %s\n", devList);
        getDevAddr = strtok( devList, delims );    // get first device address
        while (getDevAddr != NULL)
        {
            u32MsgLen = 0;
            memset(u8MsgBuf, '\0', sizeof(u8MsgBuf));

            addr = (uint16)atoi(getDevAddr);  // string address change integer
            ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], addr, u32MsgLen);
            sendHost2NodeMsg(E_SL_MSG_MANAGEMENT_LQI_REQUEST,u8MsgBuf,2);
            _DBG("Wait device LQI response.\n");
            sleep(6);

            ZG_DEBUG("LQI status: %d\n", lqiResponseDeviceStatus);
            memset(sql, '\0', SQL_BUF_MAX);
            snprintf(sql, SQL_BUF_MAX, "update devices set lqi = %d where addr = %d;", lqiResponseDeviceStatus, lqiRequestDeviceAddr);
            if (sql_update(sql) != 0)
            {
                ZG_DEBUG("Error: can not update %d LQI.\n", lqiRequestDeviceAddr);
            }

            getDevAddr = strtok( NULL, delims );    // get next device address
        }
        _DBG("GET ALL DEVICE LQI SUCCESSFUL.\n");
        return T_HANDLER_SUCCESSFUL;
    }
    else
    {
        return T_HANDLER_ERROR;
    }
}

static void add_group_handler(dbGroupTaskParameter* groupTaskParameter, char* sql)
{
    memset(sql, '\0', SQL_BUF_MAX);

    if (addGroup_task(groupTaskParameter) == 2)
    {
        snprintf(sql, SQL_BUF_MAX, "update grouptask set errl = '%s' where tid = '%s';",
                groupTaskParameter->p_errDeviceList, groupTaskParameter->p_taskId);
    }
    else   // successful clear src data on DB
    {
        snprintf(sql, SQL_BUF_MAX, "update grouptask set errl = '' where tid = '%s';", groupTaskParameter->p_taskId);
    }
	
    if (sql_update(sql) != 0)
    {
        ZG_DEBUG("Error:%d can not insert error group mark.\n", __LINE__);
        groupTaskParameter->taskStatus = T_HANDLER_ERROR;
    }

    if (sql_insert_group(groupTaskParameter->groupId, groupTaskParameter->p_successDeviceList) != 0)
    {
        ZG_DEBUG("Error:%d can not insert successful group mark.\n", __LINE__);
        groupTaskParameter->taskStatus = T_HANDLER_ERROR;
    }

    return ;
}

static void delete_group_handler(dbGroupTaskParameter* groupTaskParameter, char* sql)
{
    memset(sql, '\0', SQL_BUF_MAX);

    memset(groupTaskParameter->p_deviceList, '\0', DEVICE_LIST_MAX);
    sql_get_groups_devlist(groupTaskParameter->p_deviceList, groupTaskParameter->groupId);
    if (deleteGroup_task(groupTaskParameter) == 1)
    {
        if (sql_delete_one_item("groups", "gid", groupTaskParameter->groupId, NULL) == -1)
        {
            ZG_DEBUG("Error: can not delete gid mark.\n");
            groupTaskParameter->taskStatus = T_HANDLER_ERROR;
        }
        snprintf(sql, SQL_BUF_MAX, "update grouptask set errl = '' where tid = '%s';", groupTaskParameter->p_taskId);
        if (sql_update(sql) != 0)
        {
            ZG_DEBUG("Error:%d can not insert error group mark.\n", __LINE__);
        }

    }
    else
    {
        snprintf(sql, SQL_BUF_MAX, "update groups set dids = '%s' where gid = %d;",
                groupTaskParameter->p_errDeviceList, groupTaskParameter->groupId);
        if (sql_update(sql) != 0)
        {
            ZG_DEBUG("Error:%d can not insert error group mark.\n", __LINE__);
        }

        memset(sql, '\0', SQL_BUF_MAX);
        snprintf(sql, SQL_BUF_MAX, "update grouptask set errl = '%s' where tid = '%s';",
                groupTaskParameter->p_errDeviceList, groupTaskParameter->p_taskId);
        if (sql_update(sql) != 0)
        {
            ZG_DEBUG("Error:%d can not insert error group mark.\n", __LINE__);
        }

        groupTaskParameter->taskStatus = T_HANDLER_ERROR;
    }

    return ;
}

static void update_group_handler(dbGroupTaskParameter* groupTaskParameter, char* sql)
{
    updateGroup_task(groupTaskParameter);
    memset(sql, '\0', SQL_BUF_MAX);

    if (groupTaskParameter->taskStatus == T_HANDLER_ERROR )
    {
        snprintf(sql, SQL_BUF_MAX, "update grouptask set errl = '%s' where tid = '%s';",
                groupTaskParameter->p_errDeviceList, groupTaskParameter->p_taskId);
    }
    else
    {
        snprintf(sql, SQL_BUF_MAX, "update grouptask set errl = '' where tid = '%s';", groupTaskParameter->p_taskId);
    }
    if (sql_update(sql) != 0)
    {
        ZG_DEBUG("Error:%d can not insert error group mark.\n", __LINE__);
    }

    memset(sql, '\0', SQL_BUF_MAX);
    snprintf(sql, SQL_BUF_MAX, "update groups set dids = '%s' where gid = %d;",
            groupTaskParameter->p_deviceList, groupTaskParameter->groupId);
    if (sql_update(sql) != 0)
    {
        ZG_DEBUG("Error:%d can not update group mark.\n", __LINE__);
        groupTaskParameter->taskStatus = T_HANDLER_ERROR;
    }
}

int check_device_group_exist_status(dbGroupTaskParameter* groupTaskParameter, char* sql)
{
	char* p_getGroup = NULL;
	int   notUse = 0;
	char  groupList[256] = "\0";
	char  delims[] = ",";
	int   index = 0;
	char deviceMsg[256] = "\0";
	char* pa_device[16] = {NULL};   // 0: saddr, 1:mach, 2:macl
	char* p_device = NULL;

	extern int self_recovery_add_group(uint16 shortAddr, uint32 mach, uint32 macl);
	
	memset(sql, '\0', SQL_BUF_MAX);
	memset(groupList, '\0', 256);
	snprintf(sql, SQL_BUF_MAX, "select tid,devl from grouptask where tid = '%s';", groupTaskParameter->p_taskId);
	sql_get_ont_item(sql, GET_STRING, &notUse, groupList);

	p_getGroup = strtok(groupList, delims);
	if (p_getGroup != NULL)
	{
		memset(deviceMsg, '\0', 256);
		m_strncpy(deviceMsg, groupTaskParameter->p_taskId, 256);

		p_device = strtok(deviceMsg, delims);
		index = 0;
		while (p_device != NULL)
		{
			pa_device[index++] = p_device;
			p_device = strtok(NULL, delims);
		}
		
		lua_view_group_status(E_ZCL_AM_SHORT
			, (uint16)atoi(pa_device[0]), (uint16)atoi(p_getGroup));
		
		sleep(3);
		ZG_DEBUG("[getDeviceGroupExistStatus]: %d\n", getDeviceGroupExistStatus);
		if (getDeviceGroupExistStatus == -1)
		{
			// start group self-recovery
			self_recovery_add_group((uint16)atoi(pa_device[0])
			, (uint32)atoi(pa_device[1]), (uint32)atoi(pa_device[2]));
		}
		ZG_DEBUG("Don`t need to self-recovery device group.\n");
		groupTaskParameter->taskStatus = T_HANDLER_SUCCESSFUL;
		return 0;
	}
	groupTaskParameter->taskStatus = T_HANDLER_ERROR;
	return -1;
}

int set_all_plug_alarm_value(dbGroupTaskParameter* groupTaskParameter, char* sql)
{
	int a_sAddr[SIZE_512B] = {0};
	int plugTotalLen = 0;
	int i = 0;
	uint8 setErrorTimes = 0;
	char sAddrBuf[16] = "\0";
	uint8 errorSetFlag = 0;
	
	/* get all plug list(sAddr) */
	sql_get_all_plug_to_array(a_sAddr, &plugTotalLen);
	
	/* loop set plug alarm value */
	for (i = 0; i < plugTotalLen; i++)
	{
		_DBG("Try set sAddr %d [%d] times. Total progress %d/%d\n", a_sAddr[i], setErrorTimes+1, i, plugTotalLen);
		s_setPlugAlarmStatus = 0;
		lua_set_plug_alarm_value(a_sAddr[i], s_plugAlarmValue);
		sleep(5 + 2 * setErrorTimes);

		if (s_setPlugAlarmStatus == 0)
		{
			if (++setErrorTimes < 3)
			{
				i = i - 1; /* try set again */
				continue;
			}

			errorSetFlag = 1; /* Have plug set alarm error */
			MEMSET_STRING(sAddrBuf, 16)
			snprintf(sAddrBuf, 16, ",%d", a_sAddr[i]);
			strcat(groupTaskParameter->p_errDeviceList, sAddrBuf);
		}

		setErrorTimes = 0; /* reset error count */
	}

	memset(sql, '\0', SQL_BUF_MAX);
	if (errorSetFlag == 0)
	{
		snprintf(sql, SQL_BUF_MAX, "update grouptask set errl = '' where tid = '%s';", groupTaskParameter->p_taskId);
		groupTaskParameter->taskStatus = T_HANDLER_SUCCESSFUL;
	}
	else
	{
		snprintf(sql, SQL_BUF_MAX, "update grouptask set errl = '%s' where tid = '%s';",
                groupTaskParameter->p_errDeviceList, groupTaskParameter->p_taskId);
		groupTaskParameter->taskStatus = T_HANDLER_ERROR;
	}
	
    if (sql_update(sql) != 0)
    {
        ZG_DEBUG("Error:%d can not insert error group mark.\n", __LINE__);
        groupTaskParameter->taskStatus = T_HANDLER_ERROR;
    }

	return 0;
}

int get_enddevice_current_version(dbGroupTaskParameter* groupTaskParameter, char* sql)
{
	char devList[DEVICE_LIST_MAX] = "\0";
    uint16 addr = 0;
    uint8 u8MsgBuf[2] = {0};
    uint32 u32MsgLen = 0;
    char *getDevAddr = NULL;
    char delims[] = ",";
    uint8 getDeviceStatus = 0;

    _DBG("Start to get end device version.\n");

    if (groupTaskParameter->p_deviceList != NULL 
		&& strlen(groupTaskParameter->p_deviceList) > 3)
    {
        memset(devList, '\0', DEVICE_LIST_MAX);
		strncpy(devList, groupTaskParameter->p_deviceList, DEVICE_LIST_MAX - 1);
        getDeviceStatus = 1;
    }
    else
    {
        getDeviceStatus = sql_get_alldevice(devList);
    }

    if ( getDeviceStatus == 1)
    {
        _DBG("GET ALL DEVICE LIST: %s\n", devList);
        getDevAddr = strtok( devList, delims );    // get first device address
        while (getDevAddr != NULL)
        {
            u32MsgLen = 0;
            memset(u8MsgBuf, '\0', sizeof(u8MsgBuf));

            addr = (uint16)atoi(getDevAddr);  // string address change integer
            ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], addr, u32MsgLen);
            sendHost2NodeMsg(E_SL_MSG_READ_ENDDEVICE_CURRENT_VERSION,u8MsgBuf,2);
            sleep(5);

            ZG_DEBUG("current version : %d\n", tmpEndDeviceVersion);
            memset(sql, '\0', SQL_BUF_MAX);
            snprintf(sql, SQL_BUF_MAX, "update devices set addgls = %d where addr = %d;", tmpEndDeviceVersion, tmpEndDeviceSaddr);
            if (sql_update(sql) != 0)
            {
                ZG_DEBUG("Error: can not update %d version.\n", tmpEndDeviceSaddr);
            }

            getDevAddr = strtok( NULL, delims );    // get next device address
        }
        _DBG("GET ALL END DEVICE VERSION SUCCESSFUL.\n");
        return T_HANDLER_SUCCESSFUL;
    }
    else
    {
        return T_HANDLER_ERROR;
    }
}

void grouptask_handler(dbGroupTaskParameter* groupTaskParameter)
{
    char sql[SQL_BUF_MAX] = "\0";
    memset(groupTaskParameter->p_successDeviceList, '\0', DEVICE_LIST_MAX);
    memset(groupTaskParameter->p_successDeleteDeviceList, '\0', DEVICE_LIST_MAX);
    memset(groupTaskParameter->p_errDeviceList, '\0', DEVICE_LIST_MAX);

    if (sql_update_one_item("grouptask", "tsta", T_HANDLER_STARTING, "tid", groupTaskParameter->p_taskId) == 0)
    {
    	switch (groupTaskParameter->controlMethod)
	    {
		    case T_CTL_ADD	 :
		        add_group_handler(groupTaskParameter, sql);
		        break;
		    case T_CTL_UPDATE:
		        update_group_handler(groupTaskParameter, sql);
		        break;
		    case T_CTL_DELETE:
		        delete_group_handler(groupTaskParameter, sql);
		        break;
		    case T_CTL_GET_LQI_STATUS:
		        groupTaskParameter->taskStatus = get_device_lqi_status(NULL);
		        break;
		    case T_CTL_GET_ONE_DEVICE_LQI_STATUS:
		        groupTaskParameter->taskStatus = get_device_lqi_status(groupTaskParameter->p_deviceList);
		        break;
		    case T_CTL_SELF_RECOVERY_ADD_GROUP:
		        get_device_group_recovery(groupTaskParameter, sql);
		        break;
			case T_CTL_CHECK_DEVICE_GROUP_STATUS:
				check_device_group_exist_status(groupTaskParameter, sql);
				break;
			case T_CLT_SET_PLUG_ALARM_VALUE:
				set_all_plug_alarm_value(groupTaskParameter, sql);
				break;
			case T_CTL_GET_DEVICE_CURRENT_VERSION:
				groupTaskParameter->taskStatus = get_enddevice_current_version(groupTaskParameter, sql);
				break;
		    default:
		        break;
	    }
	}
	else
	{
		groupTaskParameter->taskStatus = T_HANDLER_ERROR;
	}

    ZG_DEBUG("Done task status: %d\n", groupTaskParameter->taskStatus);
    sql_update_one_item("grouptask", "tsta", groupTaskParameter->taskStatus
                        , "tid", groupTaskParameter->p_taskId);

}



static void processAnalyseData(void)
{
    tsMsgQueueNode *pMsgNodeData = NULL;

    while(1)
    {
        if (s_cbufferIndexRead != s_cbufferIndexWrite)
        {
            pMsgNodeData = &s_tsMsgCircleBuffer[s_cbufferIndexRead];
            analyseData(pMsgNodeData->data, pMsgNodeData->data_len);
            s_cbufferIndexRead++;
            s_cbufferIndexRead = (s_cbufferIndexRead == MAX_CBUFFER_LENTH) ? (0) : (s_cbufferIndexRead);
            //ZG_DBG("processAnalyseData: (s_cbufferIndexRead,  s_cbufferIndexWrite) = {%d, %d}\n",
            //s_cbufferIndexRead, s_cbufferIndexWrite);
        }
        else
        {
            sleep(1);
        }
    }
}


/************************************************
设置操作系统时间
参数:*dt数据格式为"2006-4-20 20:30:30"
调用方法:
    char *pt="2006-4-20 20:30:30";
    setSystemTime(pt);
#ifndef _TM_DEFINED
    struct tm {
        int tm_sec;  [0, 59]
        int tm_min;  [0, 59]
        int tm_hour;  [0, 23]
        int tm_mday;  [1,31]
        int tm_mon; [0, 11], 0 means Jan.
        int tm_year;  = actual year - 1900
        int tm_wday; [0, 6], 0 means sunday
        int tm_yday; [0, 365], 0 means 1.1
        int tm_isdst;  tm_isdst > 0, == 0, < 0
        long int tm_gmtoff;
        const char *tm_zone;
    };
#define _TM_DEFINED

date -d mm/dd/yy eg.date -d 10/17/2008
date -s hh:mm:ss eg.date -s 10:12:13
**************************************************/
int setSystemTime(char *dt)
{
    //struct rtc_time rtm;
    struct tm t,_tm;
    struct timeval tv;
    time_t timep;

    ZG_DBG("%s\n", dt);
    sscanf(dt, "%d-%d-%d %d:%d:%d", &t.tm_year,&t.tm_mon, &t.tm_mday,&t.tm_hour,&t.tm_min, &t.tm_sec);
    _tm.tm_sec = t.tm_sec;
    _tm.tm_min = t.tm_min;
    _tm.tm_hour = t.tm_hour;
    _tm.tm_mday = t.tm_mday;
    _tm.tm_mon = t.tm_mon-1;
    _tm.tm_year = t.tm_year-1900;
    timep = mktime(&_tm);
    tv.tv_sec = timep;
    tv.tv_usec = 0;
    if(settimeofday (&tv, (struct timezone *) 0) < 0)
    {
        ZG_DEBUG("Set system datatime error!/n");
        return -1;
    }
    return 0;
}


void startZigbeeNet(void)
{
#define STARTNET_COUNT    (30/PERIODIC_DELAY_SECONDS)

    do
    {
        if (startnetcount > STARTNET_COUNT)
        {
            //do nothing
        }
		else if (startnetcount == 0)
		{
			extern int initSocket(void);
            initSocket();
			startnetcount++;
		}
        else if (startnetcount == STARTNET_COUNT)
        {
            sendHost2NodeMsg(E_SL_MSG_START_NETWORK, NULL, 0);
            ZG_DEBUG("Send to start network.\n");

            startnetcount++;
        }
        else
        {
            startnetcount++;
        }
    }
    while(0);

}

void rebootSystem(void)
{
#if 0
    time_t now;
    struct tm *t;
    char *weekday[7] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};

    do // auto reboot on time
    {
        now = time(NULL);
        t = localtime(&now);  //gmtime()
        ZG_DBG("DATE: %04d/%02d/%02d ", t->tm_year+1900, t->tm_mon+1, t->tm_mday);
        ZG_DBG("TIME: %02d:%02d:%02d %s\n", t->tm_hour, t->tm_min, t->tm_sec, weekday[t->tm_wday]);
        if ((t->tm_hour == 0) && (t->tm_min == 0))
        {
            if ((t->tm_sec >= 0) && (t->tm_sec < 30))
            {
                //ZG_DBG("system reboot....\r\n");
                //sleep(PERIODIC_DELAY_SECONDS);
                //ZG_DBG("system kill processs....\r\n");
                //system("ps|grep zigbee|grep -v grep|awk '{ZG_DEBUG \"%s \", $1}'|xargs kill -9");
                //sleep(PERIODIC_DELAY_SECONDS);
                //system("reboot");
                //execv("reboot", NULL);
                //system("shutdown -r now");
            }
        }
        //sql_query_timer();
    }
    while(0);
#endif
}


void backupDB(void)
{
#define DB_SAVE_FLASH_COUNT			(180/PERIODIC_DELAY_SECONDS)  //about 180s check save status
#define DB_COMPEL_SAVE_FLASH_COUNT	(1800/PERIODIC_DELAY_SECONDS) //if more than 30min not backup DB, then compel backup one times

    static uint32 savedbcount = 0;
    do
    {
        if (backupDBswitch == 0 && (savedbcount >= DB_SAVE_FLASH_COUNT && s_needBackupDbFlag == 1))
        {
            loadOrSaveDbInTmp(1);
            savedbcount = 0;
			s_needBackupDbFlag = 0;
        }
        else
        {
            if (++savedbcount >= DB_COMPEL_SAVE_FLASH_COUNT)
            {
				s_needBackupDbFlag = 1;
			}
        }
    }
    while(0);
}


void requestEndDeviceEnergy(void)
{
    static uint32 querycount = 0;

    int i;

    do
    {
        if ((s_requestDevicePower == 1) || (querycount++ >= 30*60/PERIODIC_DELAY_SECONDS))
        {
            sql_list_device(s_deviceaddrlist, s_deviceTagList, &s_deviceaddrnum);
            _setDeviceFlag(0);
            querycount = 0;
            for (i=0; i<s_deviceaddrnum; i++)
            {
            	_DBG("sendHost2NodeMsg device Tag: %d\n", s_deviceTagList[i]);
            	if (s_deviceTagList[i] == 65)	/* smart plug */
            	{
					sendHost2NodeMsg(E_SL_MSG_READ_ATTRIBUTE_REQUEST, (uint8 *)&s_deviceaddrlist[i], 2);
				}
				else
				{
					sendHost2NodeMsg(0xA05, (uint8 *)&s_deviceaddrlist[i], 2);
                	sendHost2NodeMsg(0xA06, (uint8 *)&s_deviceaddrlist[i], 2);
				}
                

				sleep(PERIODIC_DELAY_SECONDS);
                if (s_resetflag > 1)
                {
                    if (s_deviceflag[i] == 0)
                    {
                        sql_update_device_watt(s_deviceaddrlist[i], 0);
                    }
                }
                //sleep(PERIODIC_DELAY_SECONDS);
            }
            if (s_resetflag > 1)
            {
                s_resetflag = 0;
                _resetDeviceFlag();
            }

			s_requestDevicePower = 0;
        }
    }
    while(0);

}


void requestEndDeviceInit(void)
{
    static uint32 s_initcount = 0;

    if (s_initDeviceStatus == E_INIT_WAIT)
    {
        uint8 u8MsgBuf[10] = {0};

        if ( s_need_init_device_flag == 1
			&& sql_getUninitDevice(&s_initDeviceAddr, &s_initDeviceMacH, &s_initDeviceMacL, &s_initDeviceTag) == 0)
        {
	        if (s_jn5169MacL == 0)
	        {
	                uint8 u8MsgBuf[10] = {0};
	                sendHost2NodeMsg(E_SL_MSG_IEEE_ADDRESS_REQUEST, u8MsgBuf, 10);
	        }

            s_initDeviceStatus = E_INIT_START;
            sendHost2NodeMsg(E_SL_MSG_CONFIG_REPORTING_REQUEST, u8MsgBuf, 10);
        }
		else
		{
			s_initDeviceStatus = E_INIT_FINISH;  // not find to need init device ,wait
			s_need_init_device_flag = 0;
		}
        s_initcount = 0;
    }
    else
    {
        s_initcount++;
        if (s_initcount >= 12)  //if a device init have not done in 1 minute
        {
            s_initcount = 0;
            s_initDeviceStatus = E_INIT_WAIT;
        }
    }
}

static void getDeviceLqi(void)
{
    // Gateway start 2 min, and then get all device LQI. we set ever 1h get all device LQI one times.
    static int getLqiCount = 58*60/PERIODIC_DELAY_SECONDS;

    do
    {
        if (getLqiCount++ >= 60*60/PERIODIC_DELAY_SECONDS)
        {
            get_device_lqi_status(NULL);
            getLqiCount = 0;
        }
    }
    while (0);
}

static void checkMT7688updateJN5169Status(void)
{
	int getProgressStatus = 0;
	
	getProgressStatus = sql_check_MT7688_update_JN5169_status();
	ZG_DEBUG("getProgressStatus: %d\n", getProgressStatus);
	if (getProgressStatus != -1 && getProgressStatus == 0)
	{
		initProgressTime = 1;
	}
}

void init_get_MT7688_update_JN5169_status(void)
{
	s_mt7688_update_jn5169_psta_value = sql_get_progress_status(1);
}

static void MT7688updateJN5169Task(void)
{
    static uint8 count = 0;

    s_mt7688updatejn5169Flag = 0;
	
    do
    {
        if ((initProgressTime == 1) || (count++ >= 30/PERIODIC_DELAY_SECONDS))
        {
            if ((( s_mt7688_update_jn5169_psta_value == MT7688_UPDATE_JN5169_START) && (s_wait_update_JN5169 == 0))
				|| (initProgressTime == 1))
            {
                _DBG("\nready to update JN5169.\n");
                if (MT7688ProgrammerJN5169() == 1)
                {
                    ZG_DEBUG("%s\n", "\nMT7688 Programmer JN5169 Successful.\n");
                }
                else
                {
                    ZG_DEBUG("%s\n", "\nMT7688 Programmer JN5169 Error.\n");
                }
            }

            count = 0; // reset the count
        }
    }
    while (0);
}

static void CLEAR_LOG_FILE(void)
{
	static uint16 clearLogCount = 0;
	
	if (++clearLogCount >= 180 / PERIODIC_DELAY_SECONDS
		&& get_linux_file_size(SYSTEM_LOG_FILE_URL) >= MAX_LOG_FILE_LENGTH)
	{
		// clear log file
		_DBG("CLEAR LOG FILE.\n");
		system("chmod -R 777 "SYSTEM_LOG_FILE_URL);
		system("rm "SYSTEM_LOG_FILE_URL);
	}
}

static void processPeriodicTask(void)
{
	ZG_ENTER();
    while(1)
    {
        startZigbeeNet();

        requestEndDeviceEnergy();   //device auto report to gw

        requestEndDeviceInit();

        backupDB();

//rebootSystem();

        getDeviceLqi();

        MT7688updateJN5169Task();

		CLEAR_LOG_FILE();

        sleep(PERIODIC_DELAY_SECONDS);
    }
	ZG_LEAVE();
    return;
}

int report_reset_flag(uint8 reportType, const char* readServerResponseBuf)
{
    // 0. get response msg ( report status, update device list)
    // 1. check report status
    // 2. get report successful device list


    char* responseMsg = NULL;
    char delims[] = "\n";
    int count = 0;
    char* getBufString = NULL;
	char* getJsonString = NULL;
	int devlLen = 0;
	int i = 0;
	cJSON *item;

    ZG_DEBUG("Get server response data:\n");
    ZG_DEBUG("%s\n", readServerResponseBuf);

    APPLY_MEMORY_AND_CHECK(responseMsg,SIZE_8K);
    memset(responseMsg, '\0', SIZE_8K);
    m_strncpy(responseMsg, readServerResponseBuf, SIZE_8K);

    getBufString = strtok(responseMsg, delims);
    while (getBufString != NULL)
    {
    	getJsonString = getBufString;
        count++;
        //ZG_DEBUG("Get %d buf: %s\n", count, getBufString);
        //if (count == 7) break;   // get server resport data

        getBufString = strtok(NULL, delims);
    }

	getBufString = getJsonString; // mark json data, becaus the last is NULL.

    _DBG("Analysis server resport JSON data: %s\n", getBufString);
    cJSON *root = NULL;
	root = cJSON_Parse(getBufString);
    if(root == NULL)
    {
        _DBG("get root faild !\n");
		FREE_APPLY_MEMORY(responseMsg)
        return -1;
    }

    cJSON* resportStatus = NULL;
	resportStatus = cJSON_GetObjectItem(root, "code");
    if(resportStatus == NULL)
    {
        _DBG("Error: Can not get resport status.\n");
		FREE_APPLY_MEMORY(responseMsg)
        return -1;
    }
    _DBG("code is %d\n",resportStatus->valueint);

	cJSON* ms = NULL;
	ms = cJSON_GetObjectItem(root, "ms");
	if (ms == NULL)
	{
		DBG("Error: Can not get ms.\n");
		FREE_APPLY_MEMORY(responseMsg)
        return -1;
	}

	char* p = NULL;
	cJSON* msChild = NULL;

	p = cJSON_PrintUnformatted(ms);
	msChild = cJSON_Parse(p);
	if (msChild == NULL)
	{
		_DBG("Error: Can not ms List.\n");
		FREE_APPLY_MEMORY(responseMsg)
		return -1;
	}
	
    cJSON *reportDeviceMacList = cJSON_GetObjectItem(msChild, "devl");
    if(!reportDeviceMacList)
    {
        _DBG("Error: Can not get Device Mac address List.\n");
		FREE_APPLY_MEMORY(responseMsg)
        return -1;
    }

	devlLen = cJSON_GetArraySize(reportDeviceMacList);
	_DBG("devlLen = %d\n", devlLen);

	for (i = 0; i < devlLen; i++)
	{
		item = NULL;
		item = cJSON_GetArrayItem(reportDeviceMacList, i);
		if(item == NULL) {
		    _DBG("get item faild !\n");
			FREE_APPLY_MEMORY(responseMsg)
		    return -1;
		}

		// reset report successful mark flag
		_DBG("%s\n", item->valuestring);
	    if (sql_reset_report_flag(reportType, item->valuestring) == 0)
        {
            _DBG(" reset report flag [successful].\n");
        }
        else
        {
            _DBG(" reset report flag [Error].\n");
        }
	}

    if (root)
    {
        cJSON_Delete(root);
    }


    FREE_APPLY_MEMORY(responseMsg)

    return 1;
}

void rand_report_init_count(uint32* pa_reportCount)
{
	srand((unsigned)time(NULL));

	pa_reportCount[0] = rand() % 300;
	pa_reportCount[1] = rand() % 300;
}

int report_handler(uint8 reportType, resportMsg* repMsg, char* sendMsgBuf,char* readServerResponseBuf, int (*callbackFunction)(char*))
{
    //reportPowerTime,reportDeviceStatusTime,reportAddDeviceTime
    #undef REPORT_TIME_UINT
    #define REPORT_TIME_UINT (4*3)  /* 4 task, 3 seconds check one times */

	static uint8 firstRandFlag = 1;
    static uint32 reportCount[4] = {0};
    static char* searchTimeTitleName[3]   = {"powt", "devt", "ndevt"};
    static char* searchSwitchTitleName[3] = {"pows", "devs", "ndevs"};

	if (firstRandFlag)	/* if so many gw meanwhile power on, rand report count can reduce report count for server in meanwhile */
	{
		firstRandFlag = 0;
		rand_report_init_count(reportCount);

		_DBG("init reportCount[0]:%d, reportCount[1]:%d\n", reportCount[0], reportCount[1]);
	}
	
    do
    {
        memset(readServerResponseBuf, '\0', REPORT_BUFF_SIZE);
        memset(sendMsgBuf, '\0', SIZE_15K);
        memset(repMsg->searchTimeTitleName, '\0', SIZE_16BYTE);
        memset(repMsg->searchSwitchTitleName, '\0', SIZE_16BYTE);

		if (reportType == 0)
		{
			if (stReportTimeandSwitchMsg.powerTime >= (reportCount[reportType]++) * REPORT_TIME_UINT
				|| stReportTimeandSwitchMsg.powerSwitch != 1)
				return -1;
		}
		else if (reportType == 1)
		{
			if (stReportTimeandSwitchMsg.deviceChangeTime>= (reportCount[reportType]++) * REPORT_TIME_UINT
				|| stReportTimeandSwitchMsg.deviceChangeStatus != 1
				|| s_needAnalysisDataFlag == 0)  // if not device no change status, then not report to server
				return -1;

    		s_needAnalysisDataFlag = 0; // if have device change status , clear the flag
		}
		else if (reportType == 2)
		{
			if (stReportTimeandSwitchMsg.addDeviceTime >= (reportCount[reportType]++) * REPORT_TIME_UINT
				|| stReportTimeandSwitchMsg.addDeviceSwitch != 1)
				return -1;
		}
		else if (reportType == 3)
		{
		#if 0
			if (s_plugWattMsg.plugAbnormalReportTime >= (reportCount[reportType]++) * REPORT_TIME_UINT)
			{
				return -1;
			}
			sql_get_report_ip_and_port(repMsg);
		#endif

			//if ((reportCount[reportType]++) * REPORT_TIME_UINT > 10)	/* more than 10 seconds */
			//{
			//	sql_get_report_ip_and_port(repMsg);
			//}
			sql_get_report_ip_and_port(repMsg);
		}

        //1. check report time and serverIp and server port
        if (reportType == 0 || reportType == 1 || reportType == 2)
        {
			strcpy(repMsg->searchTimeTitleName, searchTimeTitleName[reportType]);
	        strcpy(repMsg->searchSwitchTitleName, searchSwitchTitleName[reportType]);
	        if (sql_get_report_time_switch(repMsg) == -1
	                || repMsg->rpSwitch != 1
	                || repMsg->rpTime >= (reportCount[reportType]++) * REPORT_TIME_UINT)   
	        {
	            return -1;
	        }
		}


        //2. report power data
       // _DBG("Report [%s] status ready.\n", searchTimeTitleName[reportType]);
        if (callbackFunction(sendMsgBuf) == -1)
        {
        	reportCount[reportType] = 0;  // have not data to report, clear count, wait next cycle come.
            return -1;
        }

		if (reportType >= 1 && reportType <= 2)
		{
        	_DBG("[%s] Have data to report.\n", searchTimeTitleName[reportType]);
		}
		else
		{
			_DBG("PLUG ALARM HAVE DATA REPORT.\n");
		}
		
        if (report_msg2_server(sendMsgBuf, repMsg->serverIp
			, repMsg->serverPort, readServerResponseBuf) == -1)
        {
        	reportCount[reportType] = 0;  // can not connect server, clear count, wait next cycle come.
			return -1;
		}

    }
    while(0);

    reportCount[reportType] = 0;
    // reset report flag
    if (reportType == 1 || reportType == 2 || reportType == 3)
    {
		report_reset_flag(reportType, readServerResponseBuf);
	}
	
	return 0;
}

static void processReport(void)
{
	ZG_ENTER();
	
	#undef REPORT_TASK_COUNT
	#define REPORT_TASK_COUNT 4
	
    char* sendMsgBuf = NULL;
    char* readServerResponseBuf = NULL;
    resportMsg repMsg;
    int (*sqlHandler[REPORT_TASK_COUNT])(char*) = {sql_get_report_power, sql_get_report_device_status
		, sql_get_report_new_device_list, sql_get_abnormal_device_list};
    int i = 0;

    APPLY_MEMORY_AND_CHECK(sendMsgBuf,SIZE_15K);
    APPLY_MEMORY_AND_CHECK(readServerResponseBuf,REPORT_BUFF_SIZE);

    while (1)
    {
        for (i = 0; i < REPORT_TASK_COUNT; i++)
        {
            report_handler(i, &repMsg, sendMsgBuf, readServerResponseBuf, (*sqlHandler[i]));
            sleep(3);
        }
    }

    FREE_APPLY_MEMORY(sendMsgBuf);
    FREE_APPLY_MEMORY(readServerResponseBuf);
    return;
}

int check_MT7688_version(uint32 MT7688Version)
{
	return sql_check_MT7688_version(MT7688Version);
}

char* get_download_filename(const char* p_src, char* p_dst)
{
	int i = 0, j = 0;
	int index = 0;
	int srcLen = 0;

	srcLen = strlen(p_src);
	for (i = 0; i < srcLen; i++)
	{
		if (p_src[i] == '/')
		{
			index = i;
		}
	}

	for (i = index + 1; i <srcLen; i++)
	{
		p_dst[j++] = p_src[i];
	}
	p_dst[j] = '\0';

	return p_dst;
}


int download_MT7688_progress_file(char* downloadUrlList, char* fileLength, char* stringMD5, char* hw, char* p_downloadFileName)
{
	char downloadUrl[512] = "\0";
	char lastDownloadUrl[512] = "\0";
	char saveFileUrl[SIZE_2K] = "\0";
	uint32 downloadFileLength = 0;
	int i = 0, ret = 0;
	uint8 errorCount = 0;
	char* downloadFileMD5 = NULL;

	extern int http_download(char *url, char *save_path, int* fileLength);
	extern char *MD5_file (char *path, int md5_len);

	if (downloadUrlList == NULL || stringMD5 == NULL)
	{
		return -1;
	}
	
	MEMSET_STRING(downloadUrl,SIZE_512B)
	m_strncpy(downloadUrl, downloadUrlList, SIZE_512B);

	MEMSET_STRING(lastDownloadUrl,SIZE_512B)
	get_download_filename(downloadUrl, lastDownloadUrl);
	_DBG("[GET DOWNLOAD FILE NAME]: %s\n", lastDownloadUrl);

	_DBG("downloadFileName:%s\n", p_downloadFileName);
	if (p_downloadFileName == NULL) return -1;
	m_strncpy(p_downloadFileName, lastDownloadUrl, SIZE_256B);

	MEMSET_STRING(saveFileUrl,SIZE_2K)
	//strcpy(saveFileUrl, "/root/progressMT7688/");
	strcpy(saveFileUrl, "/root/");
	strcat(saveFileUrl, lastDownloadUrl);
	
	// download file from cloud server
	errorCount = 0;
	for (i = 0; i < 3; i++) // try download 3 times
	{
		_DBG("get to download url:%s, save path:%s, md5:%s.\n"
					, downloadUrl, saveFileUrl, strtolower(stringMD5));
		ret = http_download(downloadUrl, saveFileUrl, &downloadFileLength);
		_DBG("download ok file len: %d\n", downloadFileLength);

		// note: md5  need string to lower	
		if (downloadFileLength != 0)
		{
			downloadFileMD5 = MD5_file(saveFileUrl, 32);
			_DBG("DOWNLOAD file analysis MD5:%s\n", downloadFileMD5);
		}	
			
		if ((ret != 0) 
			|| (downloadFileLength == 0) 
			|| (strcmp(downloadFileMD5, strtolower(stringMD5)) != 0))
		{
			FREE_APPLY_MEMORY(downloadFileMD5)
				
			if (++errorCount > 3)
			{
				_DBG("[Download file error] -> %s\n", lastDownloadUrl);
				break;
			}
			_DBG("[Download file error: %s], try %d times.\n", lastDownloadUrl, errorCount);

			sleep(3);
			continue;
		}
		break;
	}

	FREE_APPLY_MEMORY(downloadFileMD5)
	return ((errorCount == 0) ? (0) : (-1));
}

int self_update_run_shell_script(void)
{
	int ret = 0;
	
	sleep(1);
	ret = pox_system("/root/tarscript.sh 3 /root/progressMT7688/progressGateway.sh");
	ret = pox_system("/root/tarscript.sh 3 /root/progressMT7688/configScript.txt");

	s_wait_update_JN5169 = 1; // stop update JN5169
	get_config_script_value();
	
	_DBG("[Update DB gateway version successful.][line:%d]\n", __LINE__);
	loadOrSaveDbInTmp(1); // backup DB to flash
	_DBG("Backup DB successful.\n");
	sleep(2);

	ret = pox_system("/root/tarscript.sh 4 progressGateway.sh /root/progressMT7688/progressGateway.sh");  // run update shell script
	log_zigbee_status(0,1); // /start to check watchdog status, root/logzigbee will restart  /root/zigbee
	_DBG("[!!! exit]progress MT7688 child zigbee.\n");
	exit(0);
	
	return ret;
}

char* get_request_MT7688_copyright_head(char* p_sendMsg)
{
	char gmacid[128] = "\0";
	char* p_getStringMD5 = NULL;

	if (p_sendMsg == NULL) return NULL;
	
	extern void get_gmacid(char* gmacid);
    MEMSET_STRING(gmacid, 128);
    get_gmacid(gmacid);
	m_strncpy(p_sendMsg, "{\"GMAC\":\"", SIZE_1K);
    strcat(p_sendMsg, gmacid);
	//strcat(p_sendMsg, "\",\"GETV\":\"MT7688\",\"md5\":\"12345678\"}");

	strcat(p_sendMsg, "\",\"GETV\":\"MT7688\",");
	p_getStringMD5 = MD5_string(p_sendMsg, 32);
    strcat(p_sendMsg, "\"md5\":\"");
	strcat(p_sendMsg, p_getStringMD5);
	strcat(p_sendMsg, "\"}");
	FREE_APPLY_MEMORY(p_getStringMD5)

	return p_sendMsg;
}

int MT7688SelfUpdate(void)
{
	char* p_sendMsg = NULL;
	char* p_receviceMsgBuf = NULL;
	resportMsg repMsg;
	httpRequestMsg httpMsg;
	int ret = 0;
	char* downloadFileName = NULL;
	char tarBack[SIZE_512B] = "\0";
	pid_t pid;
	
	init_http_request_msghead(&httpMsg);		// Note: must init struct pointer, then using
	APPLY_MEMORY_AND_CHECK(downloadFileName,SIZE_256B)
	APPLY_MEMORY_AND_CHECK(p_sendMsg,SIZE_1K)
	APPLY_MEMORY_AND_CHECK(p_receviceMsgBuf,REPORT_BUFF_SIZE)
	MEMSET_STRING(repMsg.searchTimeTitleName, SIZE_16BYTE)
	MEMSET_STRING(repMsg.searchSwitchTitleName, SIZE_16BYTE)
	MEMSET_STRING(p_sendMsg, SIZE_1K)
	MEMSET_STRING(p_receviceMsgBuf, SIZE_2K)
	
	strcpy(repMsg.searchTimeTitleName, "powt");   // just want to get server ip and port
    strcpy(repMsg.searchSwitchTitleName, "pows");
    if (sql_get_report_time_switch(&repMsg) == 0)
    {
    	// 1. get amd send update request
    	get_request_MT7688_copyright_head(p_sendMsg);
		if (report_msg2_server(p_sendMsg, repMsg.serverIp, repMsg.serverPort, p_receviceMsgBuf) != -1)
		{
			analysis_http_request(&httpMsg, p_receviceMsgBuf);
			_DBG("[GET DOWNLOAD MESSAGE] \n hw:%s\n url:%s\n ver:%d\n md5:%s\n"
				, httpMsg.downloadMsg.p_hw
				, httpMsg.downloadMsg.p_downloadFileAddrList
				, httpMsg.downloadMsg.u32_version
				, httpMsg.downloadMsg.p_md5);
			
			while (httpMsg.downloadMsg.p_downloadFileAddrList != NULL
				&& httpMsg.downloadMsg.p_hw != NULL
				&& httpMsg.downloadMsg.p_md5 != NULL
				&& httpMsg.downloadMsg.u32_version != 0)
			{
				_DBG("Ready to download file.\n");
				
				// 2.  if get download version with gateway version different, then download package.
				if (check_MT7688_version(httpMsg.downloadMsg.u32_version) != 0)
				{
					_DBG("Do not update MT7688.\n");
					ret = -1;
					break;
				}
				
				_DBG("[Need to download file.][line:%d]\n", __LINE__);
				MEMSET_STRING(downloadFileName,SIZE_256B)
				if (download_MT7688_progress_file(httpMsg.downloadMsg.p_downloadFileAddrList
											, httpMsg.downloadMsg.p_downloadFileLengthList
											, httpMsg.downloadMsg.p_md5
											, httpMsg.downloadMsg.p_hw
											, downloadFileName) != 0)
				{
					ret = -1;
					_DBG("[END DOWNLOAD FILE:] download file error.\n");
					break;
				}
				_DBG("[Download file successful.][line:%d]\n", __LINE__);
				
				// 3.  update DB version
				backupDBswitch = 1;  // stop auto backup DB
				if (sql_update_progress_MT7688_version(httpMsg.downloadMsg.u32_version) != 0)
				{
					backupDBswitch = 0; // update mt7688 error, start auto backup DB
					_DBG("Save new gateway version error.\n");
					ret = -1;
					break;
				}
				else
				{
					ret = pox_system("chmod -R 777 /root/tarscript.sh");
					ret = pox_system("/root/tarscript.sh 1 /root/progressMT7688/progressGateway.sh");  // delete src update shell script
					
					MEMSET_STRING(tarBack,SIZE_512B)
					strcpy(tarBack, "/root/tarscript.sh 2 /root/");
					strcat(tarBack, downloadFileName);
					strcat(tarBack, " /root/");
					ret = pox_system(tarBack);

					_DBG("Run to update MT7688 shell script.\n");
					// check zxvf srcipt successful
					if (is_file_exist("/root/progressMT7688/progressGateway.sh") != 0)
					{
						_DBG("\n\n progressGateway.sh not exist\n\n");
					}
					else
					{
						// zxvf update.gz OK
						pid = fork();
						if (pid < 0)
						{
							_DBG("UPDATE MT7688 FORK ERROR.\n");
						}
						else
						{
							if (pid == 0)
							{
								self_update_run_shell_script();
							}

							//_DBG("main zigbee enter sleep(60), wait update MT7688 script run end\n");
							//sleep(60);   // wait update MT7688 script run end, otherwise watchdog restart zigbee when progressing.
							log_zigbee_status(2,1);  // logzigbee enter progress mode, do not check watchdog status
							_DBG("[!!! exit]progress MT7688 main zigbee.\n");
							exit(0);
						}
	
					}
	
					if (sql_update_progress_MT7688_version(1) != 0)  // clear update DB version
					{
						_DBG("[!!! exit]progress MT7688 clear update DB version.\n");
						exit(0);              // logzigbee restrt  /root/zigbee
					}
									
				}// end sql save new download version

				backupDBswitch = 0;       // update mt7688 error, start auto backup DB
				break;       // out for while
			}
		
		}
		else
		{
			_DBG("Report download to server error.\n");
		}
		
		ret =  -1;
	}
	else
	{
		ret = -1;
	}

	_DBG_INDEX();
	FREE_APPLY_MEMORY(httpMsg.downloadMsg.p_downloadFileAddrList)
	FREE_APPLY_MEMORY(httpMsg.downloadMsg.p_downloadFileLengthList)
	FREE_APPLY_MEMORY(httpMsg.downloadMsg.p_hw)
	FREE_APPLY_MEMORY(httpMsg.downloadMsg.p_md5)
	FREE_APPLY_MEMORY(p_sendMsg)
	FREE_APPLY_MEMORY(p_receviceMsgBuf)
	FREE_APPLY_MEMORY(downloadFileName)

	return ret;
}

static void processMT7688Update(void)
{
	ZG_ENTER();
	static uint32 timeMT7688Count = 0;
	static uint32 timeJN5169Count = 0;
	
	sql_get_MT7688_and_JN5169_version_time(&getMT7688VersionTime, &getJN5169VersionTime);
	_DBG("getMT7688VersionTime: %d, getJN5169VersionTime: %d\n", getMT7688VersionTime, getJN5169VersionTime);
	while (1)
	{
		if (timeMT7688Count++ > (getMT7688VersionTime / 5))
		{
			_DBG("[GetMT7688VersionTime Successful]\n");
			MT7688SelfUpdate();
			timeMT7688Count = 0;
		}

		if (timeJN5169Count++ > (getJN5169VersionTime / 5))
		{
			_DBG("[GetJN5169VersionTime Successful]\n");
			// 1.  send version request
			// 2.  IF download file
			
			timeJN5169Count = 0;
		}

		sleep(5);
	}
}

static void processWatchdog(void)
{
	ZG_ENTER();
	static uint32 watchdogCount = 1;  // init 1
	static char* p_buf = NULL;
	static uint16 memoryHighCount = 0;
	static uint16 feedDogCount = 0;
		
	while (1)
	{
		if (log_zigbee_status( 1, ++watchdogCount) != 0)
		{
			_DBG("[Feed dog error]\n");
			//if (++feedDogCount >= 3)  // if continue 3 times can not feed dog successful
			//{
				_DBG("[Feed dog error: Quit] the zigbee.\n");
				log_zigbee_status( 0, 1 );
				exit(0);
			//}
		}
		else
		{
			feedDogCount = 0;
		}

		if (watchdogCount % 30 == 0)
		{
			p_buf = NULL;
			p_buf = (char*)malloc(WATCHDOG_CHECK_SYSTEM_MEMORY_MAX); // 10 M , gw total 128M
			if (p_buf == NULL)
			{
				_DBG("[Memory insufficient!] Watchdog malloc error.\n");  // maybe gw have not enough memory
				
				//if (++memoryHighCount >= 3)  // if continue 3 min can not malloc memory successful
				//{
					_DBG("[Memory insufficient: Quit] the zigbee.\n");
					log_zigbee_status( 0, 1 );
					exit(0);
				//}
			}
			else
			{
				memoryHighCount = 0;
				memset(p_buf, '1', WATCHDOG_CHECK_SYSTEM_MEMORY_MAX);
				free(p_buf);
			}
		}


		sleep(2);
	}
}

int handler_schedule_task_control_device(ScheduleHandlerMsg* scheduleMsg)
{
	switch (scheduleMsg->ctlType)
	{
		case E_ONOFF:
		{
			lua_set_device_onoff( E_ZCL_AM_BROADCAST, 0xFFFF, scheduleMsg->onoff );
			sleep(scheduleMsg->timeUnitInterval);
		}
		break;
		
		case E_LUM: 
		{
			do
			{	
				lua_set_device_lum( E_ZCL_AM_BROADCAST, 0xFFFF, scheduleMsg->lumStart);
				sleep(scheduleMsg->timeUnitInterval);
				if (scheduleMsg->lumStart + (scheduleMsg->paraUnitInterval) < 0) break;
				scheduleMsg->lumStart += scheduleMsg->paraUnitInterval;
			}
			while ((scheduleMsg->paraUnitInterval > 0) ? (scheduleMsg->lumStart < scheduleMsg->lumStop) : (scheduleMsg->lumStart > scheduleMsg->lumStop));
		}
		break;
		
		case E_CCT: 
		{
			do
			{	
				lua_set_device_cct( E_ZCL_AM_BROADCAST, 0xFFFF, scheduleMsg->cctStart);
				sleep(scheduleMsg->timeUnitInterval);
				if (scheduleMsg->cctStart + (scheduleMsg->paraUnitInterval) < 0) break;
				scheduleMsg->cctStart += scheduleMsg->paraUnitInterval;
			}
			while ((scheduleMsg->paraUnitInterval > 0) ? (scheduleMsg->cctStart < scheduleMsg->cctStop) : (scheduleMsg->cctStart > scheduleMsg->cctStop));
		}
		break;

		case E_RGB: 
		{
			do
			{	
				lua_set_device_hue( E_ZCL_AM_BROADCAST, 0xFFFF, scheduleMsg->hueStart);
				sleep(scheduleMsg->timeUnitInterval);
				if (scheduleMsg->hueStart + (scheduleMsg->paraUnitInterval) < 0) break;
				scheduleMsg->hueStart += scheduleMsg->paraUnitInterval;
			}
			while ((scheduleMsg->paraUnitInterval > 0) ? (scheduleMsg->hueStart < scheduleMsg->hueStop) : (scheduleMsg->hueStart > scheduleMsg->hueStop));
		}
		break;
	}

	return 0;
}

int handler_schedule_task(emScheduleType handlerScheduleFlag)
{
	// handler schedule task
	ScheduleHandlerMsg scheduleMsg;
	int loopCount = 0;
		
	_DBG("*** Handler schedule task flag: [%d]\n", handlerScheduleFlag);
	switch (handlerScheduleFlag)
	{
		case E_WORK:  // ON , LUM 190, CCT 190
		{
			loopCount = 0;
			scheduleMsg.timeUnitInterval = 3;
			scheduleMsg.paraUnitInterval = 10;
			do
			{
				scheduleMsg.ctlType = E_ONOFF;
				scheduleMsg.onoff= 1;	
				handler_schedule_task_control_device(&scheduleMsg);
				scheduleMsg.ctlType = E_LUM;
				scheduleMsg.lumStart = 190;
				scheduleMsg.lumStop = 190;
				handler_schedule_task_control_device(&scheduleMsg);
				scheduleMsg.ctlType = E_CCT;
				scheduleMsg.cctStart = 190;
				scheduleMsg.cctStop = 190;
				handler_schedule_task_control_device(&scheduleMsg);
			}
			while (++loopCount < 3);
		}
		break;
		
		case E_WORK2REST: // CCT 190->1, LUM 190->1, 10min later, OFF (E_WORKOUT)
		{
			scheduleMsg.timeUnitInterval = 3;
			scheduleMsg.paraUnitInterval = -5;
			scheduleMsg.ctlType = E_CCT;
			scheduleMsg.cctStart = 190;
			scheduleMsg.cctStop = 1;
			handler_schedule_task_control_device(&scheduleMsg);
			scheduleMsg.ctlType = E_LUM;
			scheduleMsg.lumStart = 190;
			scheduleMsg.lumStop = 1;
			handler_schedule_task_control_device(&scheduleMsg);
		}
		break;
		
		case E_REST2WORK: // ON, CCT: 1->190, LUM: 1->190
		{
			scheduleMsg.timeUnitInterval = 3;
			scheduleMsg.paraUnitInterval = 5;
			loopCount = 0;

			do
			{
				scheduleMsg.ctlType = E_ONOFF;      // must sure ON all device
				scheduleMsg.onoff= 1;	
				handler_schedule_task_control_device(&scheduleMsg);
			}
			while (++loopCount < 3);
			
			scheduleMsg.ctlType = E_CCT;
			scheduleMsg.cctStart = 1;
			scheduleMsg.cctStop = 190;
			handler_schedule_task_control_device(&scheduleMsg);
			scheduleMsg.ctlType = E_LUM;
			scheduleMsg.lumStart = 1;
			scheduleMsg.lumStop = 190;
			handler_schedule_task_control_device(&scheduleMsg);
		}
		break;
		
		case E_WORKOUT: // OFF all device
		{
			loopCount = 0;
			scheduleMsg.timeUnitInterval = 3;

			do
			{
				scheduleMsg.ctlType = E_ONOFF;
				scheduleMsg.onoff= 0;	
				handler_schedule_task_control_device(&scheduleMsg);
			}
			while (++loopCount < 3);
		}
		break;
		
		case E_NORMAL: // LUM:190 CCT:190
		{	
			loopCount = 0;
			scheduleMsg.timeUnitInterval = 3;
			scheduleMsg.paraUnitInterval = 10;
			do
			{
				scheduleMsg.ctlType = E_LUM;
				scheduleMsg.lumStart = 190;
				scheduleMsg.lumStop = 190;
				handler_schedule_task_control_device(&scheduleMsg);
				scheduleMsg.ctlType = E_CCT;
				scheduleMsg.cctStart = 190;
				scheduleMsg.cctStop = 190;
				handler_schedule_task_control_device(&scheduleMsg);
			}
			while (++loopCount < 3);
		}
		break;
		
		default: break;
	}
	
	return 0;
}

static void processSchedule(void)
{
	ZG_ENTER();
	time_t t;
	struct tm* local;
	emScheduleType handlerScheduleFlag;

	while (1)
	{
		t = time(NULL);
		local = localtime(&t);
		_DBG("local: %4d-%02d-%02d %02d:%02d:%02d wek:%d\n"
			,local->tm_year+1900,local->tm_mon+1,local->tm_mday,local->tm_hour,local->tm_min,local->tm_sec,local->tm_wday);

		if (local->tm_wday >= 1 && local->tm_wday <= 5)  // workday do schedule
		{
			if (sql_get_schedule_time_list(local->tm_hour, local->tm_min, &handlerScheduleFlag) == 0)
			{
				handler_schedule_task(handlerScheduleFlag);
				sleep(60);
				continue;
			}
		}

		if (((local->tm_hour >= 9 && local->tm_hour < 12) || (local->tm_hour >= 13 && local->tm_hour < 19))
			&& (local->tm_min % 10 == 0))  // work time , keep light on
		{
			handler_schedule_task(E_NORMAL);
			sleep(60);
			continue;
		}
		else if ((local->tm_hour >= 19 && local->tm_hour < 24) && (local->tm_min % 20 == 0))
		{
			handler_schedule_task(E_NORMAL);
			sleep(60);
			continue;
		}
		
		sleep(15);
	}

	return 0;
}

emReturnStatus initUart(void)
{
    struct rs232_port_t *p = NULL;

    uint32 ret = 0;

    ZG_ENTER();

    if (s_pst232port != NULL)
    {
        ZG_DBG("uart open ttyS1 ... already!!!\r\n");
        return RE_ERROR;
    }

    p = rs232_init();
    if (p == NULL)
    {
        ZG_DBG("uart init ... NOK!!!\r\n");
        return RE_ERROR;
    }

    ZG_DBG("uart init ... OK!!!\r\n");

    rs232_set_device(p, "/dev/ttyS1");   //ttyS1 for zigbee cordinator

    ret = rs232_open(p);
    if (ret)
    {
        ZG_DBG("uart open ttyS1 ... NOK!!!\r\n");
        rs232_end(p);
        return RE_ERROR;
    }

    ZG_DBG("uart open ttyS1 ... OK!!!\r\n");

#if 1
    rs232_set_baud(p, RS232_BAUD_115200);
    //rs232_set_baud(p, RS232_BAUD_460800);
    rs232_set_data(p, RS232_DATA_8);
    rs232_set_parity(p, RS232_PARITY_NONE);
    rs232_set_stop(p, RS232_STOP_1);
    rs232_set_flow(p, RS232_FLOW_OFF);
#endif

    s_pst232port = p;

    ZG_LEAVE();

    return RE_SUCCESSFUL;
}

int update_baud_rate(struct rs232_port_t * baudPort, enum rs232_baud_e baudRate)
{
#if 1
    rs232_set_baud(baudPort, baudRate);
    rs232_set_data(baudPort, RS232_DATA_8);
    rs232_set_parity(baudPort, RS232_PARITY_NONE);
    rs232_set_stop(baudPort, RS232_STOP_1);
    rs232_set_flow(baudPort, RS232_FLOW_OFF);
    return 0;
#endif
}

emReturnStatus initZigbee(void)
{
    static bool s_isInited = FALSE;

    int ret;
    pthread_t pThreadNode2HostId;

    if (s_isInited == TRUE)
    {
        ZG_DBG("zigbee is already inited!!!\r\n");
        return RE_SUCCESSFUL;
    }

#ifdef WRITE_PROCESS
    pthread_t pThreadHost2NodeId;
    host2node_msgid = msgget( (key_t)MSG_QUEUE_HOST2NODE_KYE, 0666|IPC_CREAT);
    if(host2node_msgid == -1)
    {
        ZG_DBG("input queue msgget fail");
        return RE_ERROR;
    }

    /* when input queue have data, then write to serial from this thread */
    ret = pthread_create( &pThreadHost2NodeId, NULL, (void*)processHost2NodeMsg, NULL);
    if(ret != 0)
    {
        ZG_DBG("create thread processHost2NodeMsg error\n");
		return RE_ERROR;
    }
#endif

    /* when read full message from serial, then write to read queue*/
    node2host_msgid = msgget( (key_t)MSG_QUEUE_NODE2HOST_KEY, 0666|IPC_CREAT);
    if(node2host_msgid == -1)
    {
        ZG_DBG("output queue msgget fail");
		return RE_ERROR;
    }

    ret = pthread_create( &pThreadNode2HostId, NULL, (void*)processNode2HostMsg, NULL);
    if(ret != 0)
    {
        ZG_DBG("create thread processNode2HostMsg error\n");
		return RE_ERROR;
    }

    /* when read queue have message, wirte staic array to cache */
    pthread_t pThreadDebugId;
    ret = pthread_create( &pThreadDebugId, NULL, (void*)processData, NULL);
    if(ret != 0)
    {
        ZG_DBG("create processData thread error\n");
		return RE_ERROR;
    }

    /* Analsys read queue message */
    pthread_t pThreadAnalyseDataId;
    ret = pthread_create( &pThreadAnalyseDataId, NULL, (void*)processAnalyseData, NULL);
    if(ret != 0)
    {
        ZG_DBG("create processAnalyseData thread error\n");
		return RE_ERROR;
    }

    /* loop do some task */
    pthread_t pThreadPeriodicTaskId;
    ret = pthread_create( &pThreadPeriodicTaskId, NULL, (void*)processPeriodicTask, NULL);
    if(ret != 0)
    {
        ZG_DBG("create processBook thread error\n");
		return RE_ERROR;
    }

    /* loop do some checkout  task */
    pthread_t pThreadCheckoutId;
    ret = pthread_create( &pThreadCheckoutId, NULL, (void*)processCheckout, NULL);
    if(ret != 0)
    {
        ZG_DBG("create checkout thread error\n");
		return RE_ERROR;
    }

    /* loop report  task */
    pthread_t pThreadReportId;
    ret = pthread_create( &pThreadReportId, NULL, (void*)processReport, NULL);
    if(ret != 0)
    {
        ZG_DBG("create report thread error\n");
		return RE_ERROR;
    }

	/* loop check MT7688Update copyright */
    pthread_t pThreadMT7688UpdateId;
    ret = pthread_create( &pThreadMT7688UpdateId, NULL, (void*)processMT7688Update, NULL);
    if(ret != 0)
    {
        ZG_DBG("create pThreadMT7688UpdateId thread error\n");
		return RE_ERROR;
    }
	

	/* sofe watch dog */
    pthread_t pThreadWatchdog;
    ret = pthread_create( &pThreadWatchdog, NULL, (void*)processWatchdog, NULL);
    if(ret != 0)
    {
        ZG_DBG("create pThreadWatchdog thread error\n");
		return RE_ERROR;
    }


//#define START_GW_SCHEDULE
#ifdef START_GW_SCHEDULE
	/* schedule */
    pthread_t pThreadSchedule;
    ret = pthread_create( &pThreadSchedule, NULL, (void*)processSchedule, NULL);
    if(ret != 0)
    {
        ZG_DBG("create pThreadSchedule thread error\n");
		return RE_ERROR;
    }
#endif

    ZG_DBG("zigbee create threads ... OK!!!\r\n");

    //sendHost2NodeMsg(E_SL_MSG_START_NETWORK, NULL, 0);

    s_isInited = TRUE;

    ZG_DBG("zigbee init ... OK!!!\r\n");

    return RE_SUCCESSFUL;
}

int close_src_baud(struct rs232_port_t *_stty)
{
    if (rs232_close(_stty) != RS232_ERR_NOERROR)
    {
        ZG_DEBUG("Error: Baud be close.\n");
        return 0;
    }
    else
    {
        free(_stty->pt);
        free(_stty);
        ZG_DEBUG("Baud is close.\n");
        return 1;
    }
}


/*
*	product gw
*/
void product_gw_test_loop_bsonoff(void)
{
	lua_set_device_onoff(E_ZCL_AM_BROADCAST, 0xffff, 0);
	sleep(2);
	lua_set_device_onoff(E_ZCL_AM_BROADCAST, 0xffff, 1);
	sleep(2);
}

void progress_JN5169_end_start_network(void)
{
	int i = 0;

	sleep(1);
    _DBG("start network request.\n");
	for ( i = 0; i < 3 ; i++)
    {
        sendHost2NodeMsg(E_SL_MSG_START_NETWORK, NULL, 0);
        sleep(5);

        if (openNetworkStatus == 1)
        {
            _DBG("Successful start new network.\n");
            break;
        }
    }
}

void progress_JN5169_end_update_version_and_status(int programmerStatus, int updateMajorVersion)
{
	uint16 productTestCTL = 100;
		
	if (programmerStatus == 1)
    {
        updateMajorVersion = oldMajorVersion;

        sendHost2NodeMsg(E_SL_MSG_GET_VERSION, NULL, 0);
        sleep(3);

        ZG_DEBUG("updateMajorVersion:%d, oldMajorVersion:%d\n", updateMajorVersion, oldMajorVersion);

        // update version
        if (sql_successful_progress_JN5169(updateMajorVersion) == -1)
        {
			ZG_DEBUG("[ERROR] update DB version.\n");
		}
		else
		{
			ZG_DEBUG("[Successful] update DB version\n");
		}

		s_mt7688_update_jn5169_psta_value = MT7688_UPDATE_JN5169_SUCCESSFUL;
		sql_update_progressJN5169_status(MT7688_UPDATE_JN5169_SUCCESSFUL, 1);
		loadOrSaveDbInTmp(1);  // backup DB
		
		// product gw, first have power, progress 5169 later will openNet, and control device loop on/off
#if 1
		if (initProgressTime == 1)
		{
			lua_open_network_time(180);

			while (--productTestCTL > 0)
			{
				product_gw_test_loop_bsonoff();   // product first update JN5169, update successful loop send ON, OFF by brodecast
			}
		}
#endif

    }
    else if (programmerStatus == -1)
    {
    	s_mt7688_update_jn5169_psta_value = MT7688_UPDATE_JN5169_ERROR;
        sql_update_progressJN5169_status(MT7688_UPDATE_JN5169_ERROR, 1);
    }
	
}

int MT7688ProgrammerJN5169(void)
{
    extern int JennicModuleProgrammer(const char *pcFirmwareFile, int clearE2ROMFlag);
    extern int setResetAndCLK(int flag);
    extern int Enter_Bootloader_mode(void);
    extern int Leave_Bootloader_mode(void);
    extern int sql_update_progressJN5169_status(int progressStatus,int markId);
    extern int sql_update_integer_title(char* tableName, char* titleName, uint16 titleValue, int markId);

    int programmerStatus = 0;
    int updateMajorVersion = 0;
    int i;
	static uint16 tryProgressJN5169Count = 0;

	// if first update JN5169, must clear E2ROM, else get DB select without clear E2ROM
	if (initProgressTime == 1)
	{
		s_clearE2ROMFlag = 1;
	}
	else
	{
		s_clearE2ROMFlag = sql_get_JN5169_clear_E2ROM_flag();
	}
	_DBG("Read to progress JN5169: clearE2ROM:%d\n", s_clearE2ROMFlag);
	
    // 1.save update front major version
    sendHost2NodeMsg(E_SL_MSG_GET_VERSION, NULL, 0);
    sleep(3);

    // 2. stop all thread read and write baud.
    s_mt7688updatejn5169Flag = 1;
    ZG_DEBUG("close all thread read and write baud.\n");
    sleep(1);

    if (s_pst232port != NULL && close_src_baud(s_pst232port) == 0)
    {
    	s_mt7688updatejn5169Flag = 0;
        return -1;
    }
    s_pst232port = NULL;
    initUart();
    sleep(1);

    // 3. update database progress status
    sql_update_progressJN5169_status(MT7688_UPDATE_JN5169_UPDATING, 1);

    // 4. start progress
    Enter_Bootloader_mode();
    programmerStatus = JennicModuleProgrammer(firmwareUrl, s_clearE2ROMFlag);
    Leave_Bootloader_mode();

    sleep(1);
    if (s_pst232port != NULL && close_src_baud(s_pst232port) == 1)
    {
        s_pst232port = NULL;
    }
    initUart();

    // 5. open all thread read and writd to baud.
    s_mt7688updatejn5169Flag = 0;

    // 6. progress end and build new network
	progress_JN5169_end_start_network();

    // 7. update majorVersion and progress status
    progress_JN5169_end_update_version_and_status(programmerStatus, updateMajorVersion);

	// if progress JN5169 error, total will try 3 times
	if (programmerStatus != 1 && ++tryProgressJN5169Count < 3)
	{
		MT7688ProgrammerJN5169();
	}

    return programmerStatus;
}


/*
*
*	Lua API area
*     start
*/

/*
*	openNetTime: 0 disable join  ; 1-254 open time second  ; 255 open forever
*/
int lua_open_network_time(uint8 openNetTime)
{
    uint8 u8MsgBuf[2] = "\0";
    uint32 u32MsgLen = 0;

    // forbit open net join forever status.
    if (openNetTime >= 0 && openNetTime < 255)
    {
        ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], openNetTime, u32MsgLen);
        sendHost2NodeMsg(E_SL_MSG_PERMIT_JOINING_REQUEST, u8MsgBuf, 1);
        return 0;
    }

    return -1;
}

/*
*	addrMode: 1: group (note: deviceAddr is group number) ; 2:device
*/
int lua_identify_time(uint8 addrMode, uint16 deviceAddr, uint16 identifyTime)
{
    uint8 u8MsgBuf[8] = "\0";
    uint32 u32MsgLen = 0;

    if ((addrMode == 1 || addrMode == 2) && identifyTime > 0)
    {
        memset(u8MsgBuf, '\0', 8);
        ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], addrMode, u32MsgLen);
        ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], deviceAddr, u32MsgLen);
        ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], identifyTime, u32MsgLen);
        sendHost2NodeMsg(E_SL_MSG_IDENTIFY_SEND, u8MsgBuf, 7);
        return 0;
    }
    return -1;
}

int lua_device_leave_net(uint16 shortDeviceAddr, uint32 deviceMach, uint32 deviceMacl)
{
    uint8 u8MsgBuf[13] = "\0";
    uint32 u32MsgLen = 0;

    memset(u8MsgBuf, '\0', 13);
    ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], shortDeviceAddr, u32MsgLen);
    ZNC_BUF_U32_UPD(&u8MsgBuf[u32MsgLen], deviceMach, u32MsgLen);
    ZNC_BUF_U32_UPD(&u8MsgBuf[u32MsgLen], deviceMacl, u32MsgLen);
    sendHost2NodeMsg(E_SL_MSG_MANAGEMENT_LEAVE_REQUEST, u8MsgBuf, 12);
    return 1;
}

int lua_set_device_onoff(uint8 addrMode, uint16 shortDeviceAddr, uint8 onoffStatus)
{
    uint8 u8MsgBuf[7] = "\0";
    uint32 u32MsgLen = 0;

    memset(u8MsgBuf, '\0', 7);
    ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], addrMode, u32MsgLen);
    ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], shortDeviceAddr, u32MsgLen);
    ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], onoffStatus, u32MsgLen);
    sendHost2NodeMsg(E_SL_MSG_ONOFF_NOEFFECTS, u8MsgBuf, 7);
    return 1;
}

int lua_set_device_lum(uint8 addrMode, uint16 shortDeviceAddr, uint8 lumValue)
{
    uint8 u8MsgBuf[9] = "\0";
    uint32 u32MsgLen = 0;

    memset(u8MsgBuf, '\0', 9);
    ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], addrMode, u32MsgLen);
    ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], shortDeviceAddr, u32MsgLen);
    ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], lumValue, u32MsgLen);
    sendHost2NodeMsg(E_SL_MSG_MOVE_TO_LEVEL_ONOFF, u8MsgBuf, 9);
    return 1;
}

int lua_set_device_cct(uint8 addrMode, uint16 shortDeviceAddr, uint16 cctValue)
{
    uint8 u8MsgBuf[7] = "\0";
    uint32 u32MsgLen = 0;

    cctValue = 371 - cctValue; // change value
    memset(u8MsgBuf, '\0', 7);
    ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], addrMode, u32MsgLen);
    ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], shortDeviceAddr, u32MsgLen);
    ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], cctValue, u32MsgLen);
    sendHost2NodeMsg(E_SL_MSG_MOVE_TO_COLOUR_TEMPERATURE, u8MsgBuf, 7);
    return 1;
}

int lua_set_device_hue(uint8 addrMode, uint16 shortDeviceAddr, uint16 hueValue)
{
    uint8 u8MsgBuf[10] = "\0";
    uint32 u32MsgLen = 0;

    hueValue = 257 * hueValue; // change value
    memset(u8MsgBuf, '\0', 10);
    ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], addrMode, u32MsgLen);
    ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], shortDeviceAddr, u32MsgLen);
    ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], hueValue, u32MsgLen);
    sendHost2NodeMsg(E_SL_MSG_ENHANCED_MOVE_TO_HUE_SATURATION, u8MsgBuf, 10);
    return 1;
}

int lua_view_group_status(uint8 addrMode, uint16 shortDeviceAddr, uint16 groupNumber)
{
	uint8 u8MsgBuf[8] = "\0";
    uint32 u32MsgLen = 0;

    memset(u8MsgBuf, '\0', 8);
	_DBG("View saddr:%d, groupNum:%d\n", shortDeviceAddr, groupNumber);
    ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], addrMode, u32MsgLen);
    ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], shortDeviceAddr, u32MsgLen);
    ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], groupNumber, u32MsgLen);
    sendHost2NodeMsg(E_SL_MSG_VIEW_GROUP, u8MsgBuf, 8);
    return 1;
}

char* get_ota_image_to_buffer(const char* otaFileUrl)
{
	FILE* fd;
	uint32 fileLen = 0;
	int ret = 0;
	int systemGetFileSize = 0;
	int i = 0;
	uint8 ch;
	
	if (otaFileUrl == NULL || sp_ota_image_data == NULL)
	{
		_DBG("load ota file url is null.\n");
		return NULL;
	}

	systemGetFileSize = get_linux_file_size(otaFileUrl);
	_DBG("file:%s, length:%d\n", otaFileUrl, systemGetFileSize);

	if ((fd = fopen(otaFileUrl, "rb")) == NULL)
	{
		_DBG("fopen file %s error.\n", otaFileUrl);
		return NULL;
	}

	memset(sp_ota_image_data, '\0', OTA_RAM_BUF_SIZE);
	while (1)
	{
		if ((ret = fread(&sp_ota_image_data[fileLen], 1, 1024, fd)) > 0)
		{
			fileLen += ret;
		}
		else
		{
			break;
		}
	}

	uint32 equalLen = 0;
	fseek(fd, 0, SEEK_SET);
	for (i = 0; i < systemGetFileSize; i++)
	{
		if (ret = fread(&ch, 1, 1, fd) == 1)
		{
			if (ch == sp_ota_image_data[i]) 
			{
				equalLen++;
				continue;
			}
		}
		
		_DBG("Different: fread[%d]=%x, ramBuf[%d]=%x\n", i, (unsigned char)ch, i, sp_ota_image_data[i]);
	}
	_DBG("equalLen: %d\n", equalLen);
	fclose(fd);

	
	_DBG("[Get ota image to ram buf successful.] fread length:%d, system size:%d .\n", fileLen, systemGetFileSize);
	if (fileLen == systemGetFileSize)
	{
		return sp_ota_image_data;
	}
	else
	{
		return NULL;
	}
}

int send_load_ota_file_data(uint8 addrMode, uint16 shortDeviceAddr, const char* otaFileUrl)
{
	int ret = 0;
	char tmpOta[128] = "\0";
	char u8MsgBuf[256] = "\0";
	uint32 u32MsgLen = 0;
	int i = 0;
	uint8 ch;

	MEMSET_STRING(u8MsgBuf, 256)
	ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], addrMode, u32MsgLen);
    ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], shortDeviceAddr, u32MsgLen);

	if (get_ota_image_to_buffer(otaFileUrl) == NULL)
	{
		return -1;
	}

	MEMSET_STRING(tmpOta, 128)
	for (i = 0; i < 69; i++)
	{
		ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], sp_ota_image_data[i], u32MsgLen);
	}

	sendHost2NodeMsg(E_SL_MSG_LOAD_NEW_IMAGE, u8MsgBuf, 72);
	
	return 0;
}

int lua_load_ota_image_notify(uint8 addrMode, uint16 shortDeviceAddr, uint8 blockBufSize)
{
	char u8MsgBuf[16] = "\0";
	uint32 u32MsgLen = 0;

	MEMSET_STRING(u8MsgBuf, 16)
	ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], addrMode, u32MsgLen);
    ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], shortDeviceAddr, u32MsgLen);

	if (blockBufSize < 0 || blockBufSize > 110)
	{
		blockBufSize = 64;  /* abnolmal parameter, buffer size using default value: 64 bytes */
	}
	
	ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], blockBufSize, u32MsgLen);

	sendHost2NodeMsg(E_SL_MSG_IMAGE_NOTIFY, u8MsgBuf, 16);

	return 0;
}

int send_ota_block_response(tsOtaBlockMsg* p_otaBlockMsg)
{
	char u8MsgBuf[128] = "\0";
	uint32 u32MsgLen = 0;
	int i = 0;

	MEMSET_STRING(u8MsgBuf, 128)
	ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], p_otaBlockMsg->addrMode, u32MsgLen);
    ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], p_otaBlockMsg->saddr, u32MsgLen);
	ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], p_otaBlockMsg->sqn, u32MsgLen);
	ZNC_BUF_U32_UPD(&u8MsgBuf[u32MsgLen], p_otaBlockMsg->fileOffset, u32MsgLen);  /* offset value is reqeust ? or add size */
	ZNC_BUF_U32_UPD(&u8MsgBuf[u32MsgLen], p_otaBlockMsg->fileVersion, u32MsgLen); /* requeset ? or new image */
	ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], p_otaBlockMsg->manuCode, u32MsgLen);
	ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], p_otaBlockMsg->imageType, u32MsgLen);

	if (s_otaImageMsg.otaImageTotalSize - p_otaBlockMsg->fileOffset < p_otaBlockMsg->blockSize )
	{
		_DBG("This is the last BLOCK to client.\n");
		p_otaBlockMsg->blockSize = s_otaImageMsg.otaImageTotalSize - p_otaBlockMsg->fileOffset; /* the last block */
	}	
	ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], p_otaBlockMsg->blockSize, u32MsgLen);

	_DBG("BLOCK: fileoffset:%d/%d, size:%d\n", p_otaBlockMsg->fileOffset, s_otaImageMsg.otaImageTotalSize, p_otaBlockMsg->blockSize);

#if 1
	FILE* fd;
	int ret = 0;
	uint8 ch;

	if ((fd = fopen(s_otaFileUrl, "rb")) == NULL)
	{
		_DBG("****** fopen file error.\n");
		return -1;
	}

	fseek(fd, p_otaBlockMsg->fileOffset, SEEK_SET);
	for (i = 0; i < p_otaBlockMsg->blockSize; i++)
	{
		if ((ret = fread(&ch, 1, 1, fd)) == 1)
		{
			if (ch != sp_ota_image_data[p_otaBlockMsg->fileOffset + i])
			{
				_DBG("Different: [%d] fread:%x, ramBuf:%x\n", p_otaBlockMsg->fileOffset+i, (unsigned char)ch, sp_ota_image_data[p_otaBlockMsg->fileOffset + i]);
			}
			
			ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], ch, u32MsgLen);
		}
	}

	fclose(fd);
#endif

#if 0
	if (sp_ota_image_data == NULL)
	{
		return -1;
	}

	for ( i = 0; i < p_otaBlockMsg->blockSize; i++)
	{
		ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], sp_ota_image_data[p_otaBlockMsg->fileOffset + i], u32MsgLen);
	}
#endif

	sendHost2NodeMsg(E_SL_MSG_BLOCK_SEND, u8MsgBuf, u32MsgLen);

	return 0;
}

int send_block_delay(tsOtaBlockDelayMsg* p_otaBlockDelay)
{
	char u8MsgBuf[128] = "\0";
	uint32 u32MsgLen = 0;
	int i = 0;

	MEMSET_STRING(u8MsgBuf, 128)
	ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], p_otaBlockDelay->addrMode, u32MsgLen);
	ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], p_otaBlockDelay->saddr, u32MsgLen);
	ZNC_BUF_U8_UPD(&u8MsgBuf[u32MsgLen], p_otaBlockDelay->sqn, u32MsgLen);
	ZNC_BUF_U32_UPD(&u8MsgBuf[u32MsgLen], p_otaBlockDelay->currentTime, u32MsgLen);
	ZNC_BUF_U32_UPD(&u8MsgBuf[u32MsgLen], p_otaBlockDelay->requestTime, u32MsgLen);
	ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], p_otaBlockDelay->blockDelayMs, u32MsgLen);

	sendHost2NodeMsg(E_SL_MSG_SEND_WAIT_FOR_DATA_PARAMS, u8MsgBuf, u32MsgLen);

	return 0;
}

/*
*	return : 0 not need to limit device ota, 1 need to limit device ota
*/
int limit_ota_device_handler(tsOtaBlockDelayMsg* p_otaBlockDelay)
{
	#define ONE_SECONDE_SEND_BLOCK_COUNT (2)
	#define OTA_STOP_LONG_TIME (5*60*ONE_SECONDE_SEND_BLOCK_COUNT) /* if device ota stop, wait time and clean the msg on array */
	int i = 0;
	
	for (i = 0; i < OTA_NOT_LIMIT_COUNT; i++)
	{
		if (a_otaLimitDeviceMsg[i].otaRequestCount == 0)
		{
			a_otaLimitDeviceMsg[i].saddr = p_otaBlockDelay->saddr; /*  add ota device in array */
			a_otaLimitDeviceMsg[i].otaRequestCount = 1;
			_DBG("Add device in ota array[%d]: saddr[%d]\n", i, a_otaLimitDeviceMsg[i].saddr);
			return 0;
		}
		else if (a_otaLimitDeviceMsg[i].saddr == p_otaBlockDelay->saddr)
		{
			a_otaLimitDeviceMsg[i].otaRequestCount = 1;	/* if ota is running, reset the flag */
			return 0;
		}
		else
		{
			if (a_otaLimitDeviceMsg[i].otaRequestCount++ > OTA_STOP_LONG_TIME) /* update ota device in array */
			{
				a_otaLimitDeviceMsg[i].otaRequestCount = 0; /* clean ota device in array */
				_DBG("Clean the ota array[%d]\n", i);
			}
		}
	}

	return 1; /* no more ota empty index in array, so this device need to limit when other device ota end. */
}

int reset_limit_ota_device(uint16 sAddr)
{
	int i = 0;

	for (i = 0; i < OTA_NOT_LIMIT_COUNT; i++)
	{
		if (a_otaLimitDeviceMsg[i].saddr == sAddr)
		{
			a_otaLimitDeviceMsg[i].otaRequestCount = 0;	/* ota end, clean ota device in array */
			return 0;
		}
	}
	return -1;
}

int limit_ota_endDevice_request_speed(tsOtaBlockDelayMsg* p_otaBlockDelay)
{	
	p_otaBlockDelay->currentTime = 0;
	p_otaBlockDelay->requestTime = 60;	/* limit other ota device block request speed 60s one times */
	p_otaBlockDelay->blockDelayMs = 1000;

	if (limit_ota_device_handler(p_otaBlockDelay))
	{
		send_block_delay(p_otaBlockDelay);
		return -1;	/* if send block delay, then not to send block response */
	}
	return 0; /* do not need to send block delay, so we need to send block response */
}

int lua_get_plug_rated_watt(uint16 sAddr)
{
	char u8MsgBuf[3] = "\0";
	uint32 u32MsgLen = 0;
	int i = 0;

	MEMSET_STRING(u8MsgBuf, 3)
	ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], sAddr, u32MsgLen);
	sendHost2NodeMsg(E_SL_MSG_READ_ATTRIBUTE_REQUEST_PLUG_RATED_POWER, u8MsgBuf, u32MsgLen);

	return 0;
}

int lua_set_plug_alarm_value(uint16 sAddr, uint16 plugAlarmValue)
{
	char u8MsgBuf[4] = "\0";
	uint32 u32MsgLen = 0;

	MEMSET_STRING(u8MsgBuf, 4)
	ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], sAddr, u32MsgLen);
	ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], plugAlarmValue, u32MsgLen);
	sendHost2NodeMsg(E_SL_MSG_WRITE_ATRIBUTE_SET_PLUG_ALARM_VALUE, u8MsgBuf, u32MsgLen);

	return 0;
}

int lua_get_plug_set_alarm_value(uint16 sAddr)
{
	char u8MsgBuf[3] = "\0";
	uint32 u32MsgLen = 0;

	MEMSET_STRING(u8MsgBuf, 3)
	ZNC_BUF_U16_UPD(&u8MsgBuf[u32MsgLen], sAddr, u32MsgLen);
	sendHost2NodeMsg(E_SL_MSG_READ_PLUG_SET_RATED_VALUE, u8MsgBuf, u32MsgLen);

	return 0;
}

/*
*
*	Lua API area
*     end
*/

void analysis_http_request(httpRequestMsg* httpMsg, char* receMsgBuf)
{
    char* responseMsg = NULL;
    char* getBufString = NULL;
    char* getJsonString = NULL;
    char delims[] = "\n";
    uint8 count = 0;
    cJSON* root = NULL;
    cJSON* node = NULL;

    APPLY_MEMORY_AND_CHECK(responseMsg,RECEIVE_CLIENT_REQUEST_BUFFER_SIZE);
    memset(responseMsg, '\0', RECEIVE_CLIENT_REQUEST_BUFFER_SIZE);
    m_strncpy(responseMsg, receMsgBuf, RECEIVE_CLIENT_REQUEST_BUFFER_SIZE);

	_DBG("------> GET SERVER RESPONSE: %s\n", receMsgBuf);

    getBufString = strtok(responseMsg, delims);
    while (getBufString != NULL)
    {
        getJsonString = getBufString;
        count++;
        //_DBG("Get %d buf: %s\n", count, getBufString);
		
        if (getJsonString[0] == '{'
			&& getJsonString[1] == '\"') break;   // get server resport data, but maybe have http head on the tail from data

        getBufString = strtok(NULL, delims);
    }

    getBufString = getJsonString; // mark json data, becaus the last is NULL.

    //getBufString = "{\"MH\":1009,\"GN\":36,\"ONF\":1,\"LUM\":76,\"CCT\":170,\"RGB\":0}";
   // getBufString = "{\"code\":0,\"VER\":103,\"DURL\":\",http://192.168.1.110:8080/test/user/file?filename=updateMT7688.tar.gz\",\"FLEN\":\",457882\",\"md5\":\"12345678\"}";
//	getBufString = "{\"code\":0,\"ms\":{\"hw\":\"WG7688\",\"ver\":100,\"url\":\"http://192.168.90.231:8082/file/pregressUpdate.gz\",\"md5\":\"123456789\"}}";

	_DBG("\nAnalysis server requeset JSON data:  %s\n", getBufString);
	if (getBufString == NULL)
	{
		FREE_APPLY_MEMORY(responseMsg)
		return ;
	}

    root = cJSON_Parse(getBufString);
    if(root == NULL)
    {
        _DBG("get root faild !\n");
		FREE_APPLY_MEMORY(responseMsg)
        return ;
    }

    GET_JSON_INT(root,node,"MH",httpMsg->msgHead)
    GET_JSON_INT(root,node,"OPN",httpMsg->openNetTime)
    GET_JSON_INT(root,node,"DEVA",httpMsg->devPara.sAddr)
    GET_JSON_INT(root,node,"GN",httpMsg->groupNum)
    GET_JSON_INT(root,node,"STA",httpMsg->statusValue)
    GET_JSON_INT(root,node,"PORT",httpMsg->reportMsg.cloudServerPort)
    GET_JSON_INT(root,node,"ONF",httpMsg->devPara.onoff)
    GET_JSON_INT(root,node,"LUM",httpMsg->devPara.lum)
    GET_JSON_INT(root,node,"CCT",httpMsg->devPara.cct)
    GET_JSON_INT(root,node,"RGB",httpMsg->devPara.hue)
    GET_JSON_INT(root,node,"TM",httpMsg->sendTimeApart)
	GET_JSON_INT(root,node,"POWT",httpMsg->reportMsg.powerTime)
	GET_JSON_INT(root,node,"POWS",httpMsg->reportMsg.powerSwitch)
	GET_JSON_INT(root,node,"DEVT",httpMsg->reportMsg.deviceStatusTime)
	GET_JSON_INT(root,node,"DEVS",httpMsg->reportMsg.deviceStatusSwitch)
	GET_JSON_INT(root,node,"ADEVT",httpMsg->reportMsg.addDeviceTime)
	GET_JSON_INT(root,node,"ADEVS",httpMsg->reportMsg.addDeviceSwitch)
	GET_JSON_INT(root,node,"VER",httpMsg->downloadMsg.u32_version)
	GET_JSON_INT(root,node,"code",httpMsg->downloadMsg.codeStatus)
	GET_JSON_INT(root,node,"MT",httpMsg->gatewayVersion.mt7688Version)
	GET_JSON_INT(root,node,"JN",httpMsg->gatewayVersion.jn5169Version)
	GET_JSON_INT(root,node,"BJZ",httpMsg->plugAlarmValue)  /* SET PLUG ALARM VALUE */

	node = NULL;
    node = cJSON_GetObjectItem(root, "DURL");
    if (node != NULL)
    {
    	APPLY_MEMORY_AND_CHECK(httpMsg->downloadMsg.p_downloadFileAddrList,SIZE_2K);
        memset(httpMsg->downloadMsg.p_downloadFileAddrList, '\0', SIZE_2K);
        m_strncpy(httpMsg->downloadMsg.p_downloadFileAddrList, node->valuestring, SIZE_2K);
    }

	node = NULL;
    node = cJSON_GetObjectItem(root, "FLEN");
    if (node != NULL)
    {
    	APPLY_MEMORY_AND_CHECK(httpMsg->downloadMsg.p_downloadFileLengthList,SIZE_1K);
        memset(httpMsg->downloadMsg.p_downloadFileLengthList, '\0', SIZE_1K);
        m_strncpy(httpMsg->downloadMsg.p_downloadFileLengthList, node->valuestring, SIZE_1K);
    }

    node = NULL;
    node = cJSON_GetObjectItem(root, "IP");
    if (node != NULL)
    {
        memset(httpMsg->reportMsg.cloudServerIP, '\0', 16);
        m_strncpy(httpMsg->reportMsg.cloudServerIP, node->valuestring, 16);
    }

    node = NULL;
    node = cJSON_GetObjectItem(root, "TID");
    if (node != NULL)
    {
        memset(httpMsg->p_taskId, '\0', 256);
        m_strncpy(httpMsg->p_taskId, node->valuestring, 256);
    }

    node = NULL;
    node = cJSON_GetObjectItem(root, "DEVAL");
    if (node != NULL)
    {
        APPLY_MEMORY_AND_CHECK(httpMsg->p_deviceShortAddrList,SIZE_8K);
        memset(httpMsg->p_deviceShortAddrList, '\0', SIZE_8K);
        m_strncpy(httpMsg->p_deviceShortAddrList, node->valuestring, SIZE_8K);
    }

    node = NULL;
    node = cJSON_GetObjectItem(root, "TK");
    if (node != NULL)
    {
        memset(httpMsg->tk, '\0', 128);
        m_strncpy(httpMsg->tk, node->valuestring, 128);
    }

    node = NULL;
    node = cJSON_GetObjectItem(root, "GMAC");
    if (node != NULL)
    {
        memset(httpMsg->reportMsg.gMacId, '\0', 128);
        m_strncpy(httpMsg->reportMsg.gMacId, node->valuestring, 128);
    }

// object array analysis
#if 0
	node = NULL;
    node = cJSON_GetObjectItem(root, "ms");
    if (node != NULL)
    {
		msLen = cJSON_GetArraySize(node);
		_DBG("msLen = %d\n", msLen);

		cJSON *item, *it, *js_hw, *js_ver, *js_url, *js_md5;
		char *p  = NULL;
		for (i = 0; i < msLen; i++)
		{
			item = NULL;
			item = cJSON_GetArrayItem(node, i);
			if(item == NULL) {
			    _DBG("get ms item faild !\n");
			    break;
			}

			p = cJSON_PrintUnformatted(item);
			it = NULL;
			it = cJSON_Parse(p);
			if (it == NULL)
			{
				continue;
			}

			js_hw = NULL;
			js_hw = cJSON_GetObjectItem(it, "hw");
			if (js_hw != NULL)
			{
				APPLY_MEMORY_AND_CHECK(httpMsg->downloadMsg.p_hw, SIZE_512B);
        		memset(httpMsg->downloadMsg.p_hw, '\0', SIZE_512B);
				strcpy(httpMsg->downloadMsg.p_hw, js_hw->valuestring);
			}

			js_url = NULL;
			js_url = cJSON_GetObjectItem(it, "url");
			if (js_url != NULL)
			{
				APPLY_MEMORY_AND_CHECK(httpMsg->downloadMsg.p_downloadFileAddrList, SIZE_512B);
        		memset(httpMsg->downloadMsg.p_downloadFileAddrList, '\0', SIZE_512B);
				strcpy(httpMsg->downloadMsg.p_downloadFileAddrList, js_url->valuestring);
			}

			js_md5 = NULL;
			js_md5 = cJSON_GetObjectItem(it, "md5");
			if (js_md5 != NULL)
			{
				APPLY_MEMORY_AND_CHECK(httpMsg->downloadMsg.p_md5, SIZE_256B);
        		memset(httpMsg->downloadMsg.p_md5, '\0', SIZE_256B);
				strcpy(httpMsg->downloadMsg.p_md5, js_md5->valuestring);
			}

			GET_JSON_INT(it,js_ver,"ver",httpMsg->downloadMsg.u32_version)

		}
		  	
    }
#endif

	node = NULL;
    node = cJSON_GetObjectItem(root, "ms");
    if (node != NULL)
    {
		cJSON *it, *js_hw, *js_ver, *js_url, *js_md5;
		char *p  = NULL;

		p = cJSON_PrintUnformatted(node);
		it = NULL;
		it = cJSON_Parse(p);
		if (it != NULL)
		{
			js_hw = NULL;
			js_hw = cJSON_GetObjectItem(it, "hw");
			if (js_hw != NULL)
			{
				APPLY_MEMORY_AND_CHECK(httpMsg->downloadMsg.p_hw, SIZE_512B);
	    		memset(httpMsg->downloadMsg.p_hw, '\0', SIZE_512B);
				m_strncpy(httpMsg->downloadMsg.p_hw, js_hw->valuestring, SIZE_512B);
			}

			js_url = NULL;
			js_url = cJSON_GetObjectItem(it, "url");
			if (js_url != NULL)
			{
				APPLY_MEMORY_AND_CHECK(httpMsg->downloadMsg.p_downloadFileAddrList, SIZE_512B);
	    		memset(httpMsg->downloadMsg.p_downloadFileAddrList, '\0', SIZE_512B);
				m_strncpy(httpMsg->downloadMsg.p_downloadFileAddrList, js_url->valuestring, SIZE_512B);
			}

			js_md5 = NULL;
			js_md5 = cJSON_GetObjectItem(it, "md5");
			if (js_md5 != NULL)
			{
				APPLY_MEMORY_AND_CHECK(httpMsg->downloadMsg.p_md5, SIZE_256B);
	    		memset(httpMsg->downloadMsg.p_md5, '\0', SIZE_256B);
				m_strncpy(httpMsg->downloadMsg.p_md5, js_md5->valuestring, SIZE_256B);
			}	

			GET_JSON_INT(it,js_ver,"ver", httpMsg->downloadMsg.u32_version)
		}

    }

    if (root)
    {
        cJSON_Delete(root);
    }

    FREE_APPLY_MEMORY(responseMsg)
    _DBG("[Done:]Analysis server requeset JSON data\n");
}

int http_response2server(int clientSocketId, char* sendBuf, responseFlag repFlag)
{
    int ret = 0;
    //char httpRequestHead[] = "HTTP/1.1 200 OK\r\nContent-type: text/html\r\n\r\n";
    char httpRequestHead[] = "HTTP/1.1 200 OK\r\nContent-type: application/json;charset=utf-8\r\n\r\n";
    char httpResponseBuf[1024] = "{\"GMAC\":\"";
    char gmacid[128] = "\0";
    char* sendMsgBuf = NULL;

    extern void get_gmacid(char* gmacid);
    memset(gmacid, '\0', 128);
    get_gmacid(gmacid);
    strcat(httpResponseBuf, gmacid);

    APPLY_MEMORY_AND_CHECK(sendMsgBuf,SIZE_15K);
    memset(sendMsgBuf, '\0', SIZE_15K);
    m_strncpy(sendMsgBuf, httpRequestHead, SIZE_15K);

    switch (repFlag)
    {
    case CTL_SEND_DATA:
        strcat(sendMsgBuf, sendBuf);
        break;
    case CTL_SUCCESSFUL:
        strcat(httpResponseBuf, "\",\"STA\":3}");
        break;
    case CTL_ERROR:
        strcat(httpResponseBuf, "\",\"STA\":4}");
        break;
	case CTL_SEND_TIAL:
		strcat(httpResponseBuf, sendBuf);
		break;
    default:
        strcat(httpResponseBuf, "\",\"STA\":4}");
        break;
    }
    if (repFlag != CTL_SEND_DATA)
    {
        strcat(sendMsgBuf, httpResponseBuf);
    }

    ret = write(clientSocketId, sendMsgBuf, strlen(sendMsgBuf));
    if (ret <= 0)
    {
        _DBG("Write NULL.\n");
        _DBG_INDEX();
    }
    else
    {
        _DBG("\n[Send response data:]\n%s\n", sendMsgBuf);
    }

    FREE_APPLY_MEMORY(sendMsgBuf)
    return 0;
}

int request_all_device_handler(int clientSocketId)
{
    extern int sql_get_device_list(char* sendMsgBuf);
    char* sendMsgBuf = NULL;
    char sql[SQL_BUF_MAX] = "\0";

    APPLY_MEMORY_AND_CHECK(sendMsgBuf,SIZE_15K);
    memset(sendMsgBuf, '\0', SIZE_15K);
    memset(sql, '\0', SQL_BUF_MAX);

    sprintf(sql, "select id,tag,addr,ltt,mac,name,lqi,addgls from devices;");
    sql_http_request_json_data(sendMsgBuf, sql, REQUEST_ALL_DEVICE_JSON);
    _DBG("SQL HTTP: %s\n", sendMsgBuf);
    http_response2server(clientSocketId, sendMsgBuf, CTL_SEND_DATA);

    FREE_APPLY_MEMORY(sendMsgBuf)
    return 0;
}

int search_zgw(httpRequestMsg* httpMsg, int clientSocketId)
{
    extern int sql_update_report_msg(httpRequestMsg* httpMsg);

    sql_update_report_msg(httpMsg);
    http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);

	// save DB
	_DBG("[ready save DB gateway GMAC&TK][line:%d]\n", __LINE__);
	loadOrSaveDbInTmp(1); // backup DB to flash
	_DBG("Backup DB successful.\n");
	
    return 1;
}


int make_device_leave_net(httpRequestMsg* httpMsg, int clientSocketId)
{
    extern int sql_check_and_get_device_exist_status(httpRequestMsg* httpMsg);
    extern int sql_delete_one_item(char* tableName, char* ifTitleName, int ifValue, char* ifString);
	int ret = 0;

	ret = sql_check_and_get_device_exist_status(httpMsg);
    if ( ret == 0)
    {
        // we shoult check the device if leave net successful.
        lua_device_leave_net(httpMsg->devPara.sAddr, httpMsg->devPara.mach, httpMsg->devPara.macl);
        sql_delete_one_item("devices", "addr", httpMsg->devPara.sAddr, NULL);  // delete device mark on DB
        http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
        return 0;
    }
    else if (ret == 1)
    {
		http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
        return 0;
	}
	else
    {
        http_response2server(clientSocketId, NULL, CTL_ERROR);
        return -1;
    }
}

int add_or_adjust_group_task(httpRequestMsg* httpMsg, int clientSocketId)
{
    extern int sql_insert_group_task(httpRequestMsg* httpMsg);
    if (sql_insert_group_task(httpMsg) == -1)  //ERROR
    {
        http_response2server(clientSocketId, NULL, CTL_ERROR);
        return -1;
    }
    else
    {
        http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
        return 0;
    }
}

int add_delete_group_task(httpRequestMsg* httpMsg, int clientSocketId)
{
    extern int sql_insert_delete_group_task(httpRequestMsg* httpMsg);
    if (sql_insert_delete_group_task(httpMsg) == -1) // ERROR
    {
        http_response2server(clientSocketId, NULL, CTL_ERROR);
        return -1;
    }
    else
    {
        http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
        return 0;
    }
}

int delete_task_mark(httpRequestMsg* httpMsg, int clientSocketId)
{
    extern int sql_delete_task_mark(httpRequestMsg* httpMsg);

    if (sql_delete_task_mark(httpMsg) != 0)//ERROR
    {
        http_response2server(clientSocketId, NULL, CTL_ERROR);
        return -1;
    }
    else
    {
        http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
        return 0;
    }
}

int check_task_run_status(httpRequestMsg* httpMsg, int clientSocketId)
{
    char* sendMsgBuf = NULL;
    char sql[SQL_BUF_MAX] = "\0";

    APPLY_MEMORY_AND_CHECK(sendMsgBuf,SIZE_15K);
    memset(sendMsgBuf, '\0', SIZE_15K);
    memset(sql, '\0', SQL_BUF_MAX);

    snprintf(sql, SQL_BUF_MAX, "select tsta,errl from grouptask where tid = '%s';", httpMsg->p_taskId);
    sql_http_request_json_data(sendMsgBuf, sql, REQUEST_TASK_STATUS);
    _DBG("SQL HTTP: %s\n", sendMsgBuf);
    http_response2server(clientSocketId, sendMsgBuf, CTL_SEND_DATA);

    FREE_APPLY_MEMORY(sendMsgBuf)
}

int update_task_run_status(httpRequestMsg* httpMsg, int clientSocketId)
{
    extern int sql_update_task_run_status(httpRequestMsg* httpMsg);

    if (sql_update_task_run_status(httpMsg) == -1) //error
    {
        http_response2server(clientSocketId, NULL, CTL_ERROR);
        return -1;
    }
    else
    {
        http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
        return 0;
    }
}

int add_get_device_lqi_task(httpRequestMsg* httpMsg, int clientSocketId)
{
    extern int sql_add_get_device_lqi_task(httpRequestMsg* httpMsg);

    if (sql_add_get_device_lqi_task(httpMsg) != 0) // error
    {
        http_response2server(clientSocketId, NULL, CTL_ERROR);
        return -1;
    }
    else
    {
        http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
        return 0;
    }
}

int control_device_status(httpRequestMsg* httpMsg, int clientSocketId)
{
    uint8 sendTime = 0;
    uint8 addrMode = 0;
    uint16 sAddr = 0;

	http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);

    if (httpMsg->groupNum == 0) // set device status
    {
        addrMode = E_ZCL_AM_SHORT;
        sendTime = 1;
        sAddr = httpMsg->devPara.sAddr;
    }
    else  // set group status
    {
        addrMode = E_ZCL_AM_GROUP;
        sAddr = httpMsg->groupNum;
        if (httpMsg->sendTimeApart == 0 ||
                httpMsg->sendTimeApart < 0 )   // adjust send time
        {
            sendTime = 1;
        }
        else
        {
            sendTime = httpMsg->sendTimeApart;
        }
    }

    _DBG("[SET] sAddr:%d, onoff:%d, lum:%d, cct:%d, hue:%d\n", sAddr, httpMsg->devPara.onoff
         , httpMsg->devPara.lum, httpMsg->devPara.cct, httpMsg->devPara.hue);

    if (httpMsg->devPara.onoff == 0 || httpMsg->devPara.onoff == 1)
    {
        lua_set_device_onoff(addrMode, sAddr, (uint8)httpMsg->devPara.onoff);
        sleep(sendTime);
    }

    if (httpMsg->devPara.lum >= 0 && httpMsg->devPara.lum < 256)
    {
        lua_set_device_lum(addrMode, sAddr, (uint8)httpMsg->devPara.lum);
        sleep(sendTime);
    }

    if (httpMsg->devPara.cct >= 0 && httpMsg->devPara.cct < 215)
    {
        lua_set_device_cct(addrMode, sAddr, (uint16)httpMsg->devPara.cct);
        sleep(sendTime);
    }

    if (httpMsg->devPara.hue >= 0 && httpMsg->devPara.hue < 256)
    {
        lua_set_device_hue(addrMode, sAddr, (uint16)httpMsg->devPara.hue);
        sleep(sendTime);
    }

    return 1;
}

void init_http_request_msghead(httpRequestMsg* httpMsg)
{
    httpMsg->p_deviceShortAddrList = NULL;
    httpMsg->sendTimeApart = 0;
    httpMsg->groupNum = 0;
	MEMSET_STRING(httpMsg->tk, 128)
	
    httpMsg->devPara.onoff = -1;
    httpMsg->devPara.lum = -1;
    httpMsg->devPara.cct = -1;
    httpMsg->devPara.hue = -1;
	
	httpMsg->reportMsg.powerTime = 3600;
	httpMsg->reportMsg.powerSwitch = 1;
	httpMsg->reportMsg.deviceStatusTime = 300;
	httpMsg->reportMsg.deviceStatusSwitch = 1;
	httpMsg->reportMsg.addDeviceTime = 10;
	httpMsg->reportMsg.addDeviceSwitch = 0;
	MEMSET_STRING(httpMsg->reportMsg.gMacId, 128);
    httpMsg->reportMsg.cloudServerPort = 5000;
    MEMSET_STRING(httpMsg->reportMsg.cloudServerIP, 16);

	httpMsg->downloadMsg.p_downloadFileAddrList = NULL;
	httpMsg->downloadMsg.p_downloadFileLengthList = NULL;
	httpMsg->downloadMsg.p_hw= NULL;
	httpMsg->downloadMsg.p_md5= NULL;
	httpMsg->downloadMsg.u32_version = 0;
}


int update_report_parameter(httpRequestMsg* httpMsg, int clientSocketId)
{
	if (update_report_msg_struct(httpMsg) == 0
		&& sql_update_report_parameter(httpMsg) == 0)
	{
		http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
		return 0;
	}
	else
	{
		http_response2server(clientSocketId, NULL, CTL_ERROR);
		return -1;
	}
}

int start_MT7688_update_JN5169(int clientSocketId)
{
	if (sql_start_MT7688_update_JN5169() == 0)
	{
		s_mt7688_update_jn5169_psta_value = MT7688_UPDATE_JN5169_START;
		http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
		return 0;
	}
	else
	{
		http_response2server(clientSocketId, NULL, CTL_ERROR);
		return -1;
	}

}

int get_MT7688_update_JN5169_status(int clientSocketId)
{
	char sendBuf[256] = "\0";
	int getStatus;
	char getStatusString[16] = "\0";

	memset(sendBuf, '\0', 256);
	strcpy(sendBuf, "\",\"PSTA\":");
	
	getStatus = sql_get_progress_status(1);
	if (getStatus < 1)
	{
		strcat(sendBuf, "4}");
	}
	else
	{
		memset(getStatusString, '\0', 16);
		sprintf(getStatusString, "%d", getStatus);
		strcat(sendBuf, getStatusString);
		strcat(sendBuf, "}");
	}

	http_response2server(clientSocketId, sendBuf, CTL_SEND_TIAL);
	
	return 0;
}

int set_load_ota_file_data(httpRequestMsg* httpMsg, int clientSocketId)
{
	http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
	send_load_ota_file_data(2, 0x0000, s_otaFileUrl);
	
	return 0;
}

int send_ota_image_notify_msg(httpRequestMsg* httpMsg, int clientSocketId)
{
	http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
	lua_load_ota_image_notify(4, 0xfffc, s_otaImageMsg.otaImageBufferSize);

	return 0;
}

int get_all_device_current_version(httpRequestMsg* httpMsg, int clientSocketId)
{
	extern int sql_add_get_device_lqi_task(httpRequestMsg* httpMsg);

	_DBG("Add to read End device current version task.\n");

	/* lqi and get version api using a same API, because they also add task to handler. */
    if (sql_add_get_device_lqi_task(httpMsg) != 0) // error
    {
        http_response2server(clientSocketId, NULL, CTL_ERROR);
        return -1;
    }
    else
    {
        http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
        return 0;
    }
}

int api_test_rs232_transmit_speed(httpRequestMsg* httpMsg, int clientSocketId)
{
	_DBG("API:api_test_rs232_transmit_speed, GET:timeMs[%d]\n", httpMsg->groupNum);
	sTestTransmitSpeedMs = httpMsg->groupNum;
	http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
	
	return 0;
}

int modify_gateway_update_request_time(httpRequestMsg* httpMsg, int clientSocketId)
{
	if (sql_modify_gateway_update_request_time(httpMsg) == 0)
	{
		getMT7688VersionTime = httpMsg->gatewayVersion.mt7688Version;  // modify gateway request time
		http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
	}
	else
	{
		http_response2server(clientSocketId, NULL, CTL_ERROR);
		return -1;
	}

	return 0;
}

int get_gateway_chip_version(int clientSocketId)
{
	char sendBuf[256] = "\0";
	uint32 f_getMT7688Version = 0;
	uint32 f_getJN5169Version = 0;
	char chipVersionString[16] = "\0";

	MEMSET_STRING(sendBuf,256)
	if (sql_get_gateway_chip_version(&f_getMT7688Version, &f_getJN5169Version) == 0)
	{
		strcpy(sendBuf, "\",\"MTV\":");
		MEMSET_STRING(chipVersionString,16)
		sprintf(chipVersionString, "%d", f_getMT7688Version);
		strcat(sendBuf, chipVersionString);
		
		strcat(sendBuf, ",\"JNV\":");
		MEMSET_STRING(chipVersionString,16)
		sprintf(chipVersionString, "%d", f_getJN5169Version);
		strcat(sendBuf, chipVersionString);
		strcat(sendBuf, "}");
	}
	else
	{
		strcpy(sendBuf, "\",\"MTV\":0,\"JNV\":0}");
	}
	
	http_response2server(clientSocketId, sendBuf, CTL_SEND_TIAL);
	return 0;
}

int start_request_device_power(int clientSocketId)
{
	s_requestDevicePower = 1;
	http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
	return 0;
}

int update_abnormal_plug_parameter(httpRequestMsg* httpMsg, int clientSocketId)
{
	// update DB parameter and global variable
	return 0;
}

int set_pulg_alarm_watt_value(httpRequestMsg* httpMsg, int clientSocketId)
{
	s_plugAlarmValue = httpMsg->plugAlarmValue;
	http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
	/* update all plug reted watt, add task to handler */
	sql_add_task_handler_set_plug_alarm_value(httpMsg->plugAlarmValue);
	
	/* update DB plug alarm value */
	_DBG("UPDATE PLUG ALARM VALUE: [%d]\n", s_plugAlarmValue);
	sql_update_plug_alarm_value(s_plugAlarmValue);
	return 0;
}



void init_plug_abnormal_parameter(void)
{
	s_plugWattMsg.plugNeed2CheckFlag = 1;
	if (sql_init_plug_abnormal_parameter(
		&s_plugWattMsg.plugAbnormalReportTime
		,&s_plugWattMsg.plugConfigChangeReportValue
		,&s_plugWattMsg.plugReportLimitValue) != 0)
	{
		_DBG(" [Error get DB data to init plug abnormal prarmeter]\n");
		s_plugWattMsg.plugAbnormalReportTime = 10;
		s_plugWattMsg.plugConfigChangeReportValue = 1;
		s_plugWattMsg.plugReportLimitValue = 500;
	}
	
	_DBG("Init plug: report time: %d"
		", Limit value: %d"
		", config change value: %d\n",
		s_plugWattMsg.plugAbnormalReportTime
		,s_plugWattMsg.plugConfigChangeReportValue
		,s_plugWattMsg.plugReportLimitValue
	);
}

int gw_server_handler_enter(char* receMsgBuf, int clientSocketId)
{
    // Analysis message head, and then case handler function
    httpRequestMsg httpMsg;

	// receive the server request, first response msg
    init_http_request_msghead(&httpMsg);
    analysis_http_request(&httpMsg, receMsgBuf);
	s_needBackupDbFlag = 1; // ready to backup DB
	
    switch (httpMsg.msgHead)
    {
	/* Normal API */
    case 1001:
		http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
        lua_open_network_time(httpMsg.openNetTime);
        break;
    case 1002:
        search_zgw(&httpMsg, clientSocketId);
        break;
    case 1003:
        request_all_device_handler(clientSocketId);
        break;
    case 1004:
		http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
        lua_identify_time(2, httpMsg.devPara.sAddr, 3);   
        break;
    case 1005:
        make_device_leave_net(&httpMsg, clientSocketId);
        break;
    case 1009:
        control_device_status(&httpMsg, clientSocketId);
        break;
    case 1010:
        control_device_status(&httpMsg, clientSocketId);
        break;
    case 1011:
		http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
        lua_identify_time(1, httpMsg.groupNum, 3);
        break;
    case 1012:
        add_or_adjust_group_task(&httpMsg, clientSocketId);
        break;
    case 1013:
        add_delete_group_task(&httpMsg, clientSocketId);
        break;
    case 1014:
        delete_task_mark(&httpMsg, clientSocketId);
        break;
    case 1015:
        check_task_run_status(&httpMsg, clientSocketId);
        break;
    case 1016:
        update_task_run_status(&httpMsg, clientSocketId);
        break;
    case 1017:
        add_get_device_lqi_task(&httpMsg, clientSocketId);
        break;
	case 1018:
		update_report_parameter(&httpMsg, clientSocketId);
		break;
	case 1019:
		modify_gateway_update_request_time(&httpMsg, clientSocketId);
		break;
	case 1020:
		get_gateway_chip_version(clientSocketId);
		break;
	case 1021:
		start_request_device_power(clientSocketId);
		break;
	case 1022:
		update_abnormal_plug_parameter(&httpMsg, clientSocketId);
		break;
	case 1023:
		set_pulg_alarm_watt_value(&httpMsg, clientSocketId);
		break;
	/* Expecal API */
    case 5001:
		start_MT7688_update_JN5169(clientSocketId);
        break;
    case 5002:
		get_MT7688_update_JN5169_status(clientSocketId);
        break;
	case 5003:
		set_load_ota_file_data(&httpMsg, clientSocketId);
		break;
	case 5004:
		send_ota_image_notify_msg(&httpMsg, clientSocketId);
		break;
	case 5005:
		get_all_device_current_version(&httpMsg, clientSocketId);
		break;
	
	/* Test API */
	case 9001:
		api_test_rs232_transmit_speed(&httpMsg, clientSocketId);
		break;
	case 9002:
		/* test function */
		_DBG("Test API: %s\n", "sql_delete_group_mark_to_devices");
		sql_delete_group_mark_to_devices(3, "141235234712629");
		break;
	case 9003:
		lua_get_plug_rated_watt(httpMsg.devPara.sAddr);
		http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
		break;
	case 9004:
		lua_set_device_onoff(E_ZCL_AM_BROADCAST, 0xffff, httpMsg.devPara.onoff);
		http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
		break;
	case 9005:
		lua_set_plug_alarm_value(httpMsg.devPara.sAddr, httpMsg.plugAlarmValue);
		http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
		break;
	case 9006:
		lua_get_plug_set_alarm_value(httpMsg.devPara.sAddr);
		http_response2server(clientSocketId, NULL, CTL_SUCCESSFUL);
		break;

    default:
        http_response2server(clientSocketId, NULL, CTL_ERROR);
		break;
    }

	FREE_APPLY_MEMORY(httpMsg.p_deviceShortAddrList)
	FREE_APPLY_MEMORY(httpMsg.downloadMsg.p_downloadFileAddrList)
	FREE_APPLY_MEMORY(httpMsg.downloadMsg.p_downloadFileLengthList)
	
    return 1;
}

/*
*	Gateway system run complete, about 40 seconds
*	test gateway power ON 45 seconds, then gateway power OFF
*	test writing flash status when power on to power off
*/
void test_gateway_onoff_wirte_flash_status(void)
{
	srand((unsigned)time(0)); 

	while (1)
	{
		system("chmod -R 777 /usr/lib/iot/ZigbeeNodeControlBridge_JN5169.bin");
		system("chmod -R 777 /root/ZigbeeNodeControlBridge_JN5169.bin");
		system("rm /root/ZigbeeNodeControlBridge_JN5169.bin");
		system("cp /usr/lib/iot/ZigbeeNodeControlBridge_JN5169.bin /root/ZigbeeNodeControlBridge_JN5169.bin");
	
		switch (rand()%5)
		{
			case 0: usleep(1000*100); break;
			case 1: usleep(1000*200); break;
			case 2: usleep(1000*300); break;
			case 3: usleep(1000*400); break;
			case 4: usleep(1000*500); break;
			default: break;
		}
	}

}

void test_leak_memory(void)
{
	char* leakBuf = NULL;
	int leakBufIndex = 0;

#define LEAK_BUFSIZE (1024*1024*10)
	_DBG("Enter main while loop.\n");
    while(1)
    {
		leakBuf = (char*)malloc(LEAK_BUFSIZE);
		if (leakBuf == NULL)
		{
			_DBG("leakBuf is NULL.\n");
		}
		else
		{
			memset(leakBuf, '1', LEAK_BUFSIZE);
			_DBG("ok malloc leadBuf: [%d].\n", leakBufIndex++);
			
			free(leakBuf);  /*  not free, test system memory leak  */
		}		
		
        usleep(1000*1000);
    }
	
}

void test_rs232_transmit_speed(uint32 sendTimeMs)
{
	uint8 openTime = 5;
	uint8 cmdBuf[32] = {0};
	uint32 cmdBuf_len = 0;

	if (sendTimeMs == 0)
	{
		_DBG("sendTimeMs is 0, return.\n");
		return;	/* exit test rs232_transmit speed */
	}
	else
	{
		
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], E_SL_MSG_PERMIT_JOINING_REQUEST, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0x0004, cmdBuf_len );
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], DEFAULT_CHKNUM, cmdBuf_len );
        ZNC_BUF_U16_UPD( &cmdBuf[cmdBuf_len], 0xFFFC, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], openTime, cmdBuf_len);
        ZNC_BUF_U8_UPD( &cmdBuf[cmdBuf_len], 0, cmdBuf_len);
        _DBG("Send open net time: %d\n", openTime);

		write_ex(cmdBuf, cmdBuf_len);
	
		usleep(1000*sendTimeMs);
	}
}


emReturnStatus init_ota_endDevice_msg(void)
{
	s_otaImageMsg.otaImageManufactureCode = 0x119D;
	s_otaImageMsg.otaImageType = 0;
	s_otaImageMsg.otaImageVersion = 0;
	s_otaImageMsg.otaImageBufferSize = 0x64;  /* ota send block default is 64 bytes. */
	s_otaImageMsg.otaImageTotalSize = 0;

	sp_ota_image_data = NULL;
	if ((sp_ota_image_data = (unsigned char*)malloc(OTA_RAM_BUF_SIZE)) == NULL) /* SAVE ota image data */
	{
		_DBG("Malloc ota image ram buf error.\n");
		return RE_ERROR;
	}

	send_load_ota_file_data(2, 0x0000, s_otaFileUrl); /* if exist ota file, when gw power on, auto load image */

	return RE_SUCCESSFUL;
}

void init_plug_alarm_value(void)
{
	int ret = sql_init_plug_alarm_value();

	if (ret > 0)
	{
		s_plugAlarmValue = ret;
		_DBG("DB INIT PLUG ALARM VALUE IS [%d]\n", s_plugAlarmValue);
		return ;
	}
	_DBG("[XXXXX] DB not get value, so using static value is [%d]\n", s_plugAlarmValue);
}

void init_rs232_task_count(void)
{
#ifdef RS232_TASK_COUNT 
	sRS232TaskCount.readTaskCount = 0;
	sRS232TaskCount.writeTaskCount = 0;
	
	pthread_mutex_init(&sRS232TaskCount.readTaskCountLock, NULL);
	pthread_mutex_init(&sRS232TaskCount.writeTaskCountLock, NULL);
	_DBG("init rs232 task count successful.\n");
#endif
}

void init_gateway_system(void)
{
	extern int initGpio(void);
    extern int initDb(void);
    extern int initSocket(void);
    extern int sql_get_progress_status(int markId);
    extern emReturnStatus init_gmacid(void);
    extern emReturnStatus init_pthread_lock(void);
    extern int destroy_pthread_lock(void);
	extern int http_download(char *url, char *save_path, int* fileLength);
	extern emReturnStatus socket_init_report_tk(void);

	system("killall -9 tarscript.sh");   // must kill running script, then logzigbee can check watchdog status
	system("rm /root/*.gz");
	log_zigbee_status(1,2);
	_DBG("\n\n[START] Zigbee thread version is : %s -- %s\n\n", __TIME__, __DATE__);

	do 
	{
		if (RE_ERROR == initUart()) break;
	    if (RE_ERROR == init_pthread_lock()) break;			/* init the mutex for DB */
	    if ( -1 == initDb()) break;
		if (RE_ERROR == init_db_data()) break; 			/* init DB progress and report data */
		if (RE_ERROR == init_report_msg_struct()) break;
		if (RE_ERROR == init_gmacid()) break;
		if (RE_ERROR == socket_init_report_tk()) break;
		checkMT7688updateJN5169Status();
		init_get_MT7688_update_JN5169_status();
		init_plug_abnormal_parameter();						/* note: must statement later from init_db_data */
		init_rs232_task_count();
		init_plug_alarm_value();	/* plug alarm value */
		// if (RE_ERROR == init_ota_endDevice_msg()) break; /* auto load image error, because message queue not create when before than zigbee thread init. */
		if (RE_ERROR == initZigbee()) break;				/*  init thread to work */
		if (RE_ERROR == init_ota_endDevice_msg()) break; /* malloc ota ram buf */

		_DBG(" *** Gateway init successful\n\n");
		return;
	}
	while (0);

	_DBG(" *** Gateway init error, ready to exist thread.\n\n");
	exit(0);
   
}


int main(int argc, char *argv[])
{
	init_gateway_system();

	while (1)
	{
		//test_rs232_transmit_speed(sTestTransmitSpeedMs);
		sleep(1);
	}

    //destroy_pthread_lock();    // when zigbee thread exit or be killed, system auto recycle resource
    return 0;
}


