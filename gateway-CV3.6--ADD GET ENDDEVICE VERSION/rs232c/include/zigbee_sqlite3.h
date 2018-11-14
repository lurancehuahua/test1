#ifndef _ZIGBEE_SQLITE3_H__
#define _ZIGBEE_SQLITE3_H__

#include "zigbee.h"

typedef struct
{
    char name[128];
	char mact[64];
    //unsigned char note[128];
    //unsigned long mac;
    unsigned int mach;
    unsigned int macl;
    unsigned short addr;
    unsigned short tag;
    unsigned char sta;
}zgw_device_t;


int sql_insert_device(zgw_device_t *device);
int sql_update_device(zgw_device_t *device);
int sql_delete_device(zgw_device_t *device);
int sql_list_device(unsigned short *addrlist, unsigned short *deviceTaglist, unsigned int *num);
int sql_query_device(unsigned short addr);
int sql_query_timer(void);
int sql_getUninitDevice(unsigned short *addr, unsigned int *mach, unsigned int *macl, unsigned short *tag);


int sql_query_mac(char *mac);
int sql_insert_mac(char *mac);

int sql_update_device_onoff(unsigned short addr, unsigned char onoff);
int sql_update_device_lum(unsigned short addr, unsigned char lum);
int sql_update_device_ct(unsigned short addr, unsigned short ct);
int sql_update_device_hue(unsigned short addr, unsigned char hue);
int sql_update_device_lifetime(unsigned short addr, unsigned short onhour, unsigned short offhour);
int sql_update_device_energy(unsigned short addr, unsigned int totaluseenergyh, unsigned int totaluseenergyl);
int sql_update_device_ott(unsigned short addr, unsigned char ott);
int sql_update_device_watt(unsigned short addr, unsigned short watt);

unsigned short _query_device_onh(unsigned short addr);
int loadOrSaveDbInTmp(int flag);


int initDb(void);

int sql_get_report_time_switch(resportMsg* repMsg);
int sql_get_report_power(char* sendMsgBuf);
int sql_get_report_device_status(char* sendMsgBuf);
int sql_get_report_new_device_list(char* sendMsgBuf);
int sql_get_abnormal_device_list(char* sendMsgBuf);



int sql_reset_report_flag(uint8 reportType, char* getDeviceMacAddr);

int sql_http_request_json_data(char* sendMsgBuf, char* sql, httpRequestType requestType);
int sql_get_ont_item(char* sql, getDateType getType, int* getInt, char* getString);
int sql_add_group_mark_to_devices(uint16 groupNum, char* deviceMac);
int sql_delete_group_mark_to_devices(uint16 groupNum, char* deviceMac);


int sql_get_db_grouptask(dbGroupTaskParameter* groupTaskParameter);
int sql_check_MT7688_update_JN5169_status(void);
int sql_successful_progress_JN5169(int updateMajorVersion);
int sql_update_report_parameter(httpRequestMsg * httpMsg);
int sql_start_MT7688_update_JN5169(void);
int sql_get_MT7688_and_JN5169_version_time(uint32* p_getMT7688VersionTime
															, uint32* p_getJN5169VersionTime);
int sql_update_progress_MT7688_version(uint32 newVersion);
int sql_check_MT7688_version(uint32 MT7688Version);
int sql_modify_gateway_update_request_time(httpRequestMsg* httpMsg);
int sql_get_gateway_chip_version(uint32* f_getMT7688Version, uint32* f_getJN5169Version);
int sql_init_report_tk_buffer(char* tkBuf);
int sql_set_JN5169_clear_E2ROM(int _clearE2ROM);
int sql_get_JN5169_clear_E2ROM_flag(void);
emReturnStatus init_db_data(void);
int sql_check_device_join_group_status(int groupNum, const char* devMacAddr);
int sql_get_schedule_time_list(int timeHour, int timeMin, emScheduleType* scheduleFlag);
int sql_init_report_msg_struct(stReportTimeandSwitch* stReportandSwitch);
int sql_get_report_ip_and_port(resportMsg* repMsg);
int sql_update_plug_ratedwatt(uint16 u16MsgNwkAddr, uint16 u16PlugRatedWatt);
int sql_add_task_handler_set_plug_alarm_value(uint16 plugAlarmValue);
int sql_get_all_plug_to_array(int* pa_sAddr, int* plugTotalLen);
int sql_get_device_tag_and_rated_watt(uint16 u16DeviceAddr, uint16* pu16DeviceTag, uint16* pu16DeviceRatedWatt);
int sql_set_plug_alarm_flag(uint16 deviceSaddr);




















#endif
