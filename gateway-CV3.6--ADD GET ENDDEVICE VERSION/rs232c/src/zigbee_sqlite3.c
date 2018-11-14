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
#include <sqlite3.h>
#include <pthread.h>

#include "zigbee_sqlite3.h"
#include "zigbee.h"

static char gMacId[128] = "\0";
pthread_mutex_t lockDB;


#define NOT_FIRST_JSON_OBJECT(sendMsgBuf,i) {if (i != ncol){ \
		strcat(sendMsgBuf, ","); \
	}}


#define ZGW_DB "/tmp/zgw.db"
#define ZGW_DB_FLASH "/root/zgw.db"

#define MAX_SQL_LEN    8192  /* 8k */



#define IF_SQL_ERR(ret,conn)	if(ret != SQLITE_OK){  \
       							 SQL_DEBUG("ret = %s, file:%s fun:%s line:%d\n", \
       							 sqlite3_errmsg(conn), __FILE__, __FUNCTION__, __LINE__);\
       							 sqlite3_close(conn);\
       							 FREE_LOCK(lockDB)\
        						 return -1;\
    							}

#define IF_OPEN_DB_ERR(ret,conn)     if(ret != SQLITE_OK){\
        SQL_ERR("ret = %s, file:%s fun:%s line:%d\n", sqlite3_errmsg(conn),\
        __FILE__, __FUNCTION__, __LINE__);\
        FREE_LOCK(lockDB)\
        return -1;\
    }


#define PRINTERROR(str) \
    do{ \
        perror(str);\
        exit(EXIT_FAILURE); \
    }while(0)



static int executeNoQuery(sqlite3 *db,const char *sql);
static int executeWithQuery(sqlite3 *db,char ***result,int *col,const char *sql);


unsigned int _query_device_uenh(void);
unsigned int _query_device_uenl(void);
unsigned short _query_device_watt(void);
unsigned short _query_device_offh(unsigned short addr);
int loadOrSaveDbInMemory(sqlite3 *pInMemeory, const char *zFilename, int isSave);
static int _query_mark_exist_status(char* searchSql);
static int _query_device_with_addr_mac(uint16 addr, uint32 mach, uint32 macl);
static int _query_delete_mark(char* searchSql);
static int _query_delete_device_byaddr(uint16 addr);
int sql_get_ont_item(char* sql, getDateType getType, int* getInt, char* getString);

extern char* MD5_string(const char* srcBuf, int md5_len);

emReturnStatus init_pthread_lock(void)
{
    pthread_mutex_init(&lockDB, NULL);
    return RE_SUCCESSFUL;
}

int destroy_pthread_lock(void)
{
    pthread_mutex_destroy(&lockDB);
    return 1;
}

static int executeNoQuery(sqlite3 *db,const char *sql)
{
    sqlite3_stmt *pstmt = NULL;

    if(sqlite3_prepare_v2(db,sql,strlen(sql),&pstmt,NULL) != SQLITE_OK)
    {
        if(pstmt != NULL)
        {
            sqlite3_finalize(pstmt);
        }
        return -1;
    }
    if(sqlite3_step(pstmt) != SQLITE_DONE)
    {
        sqlite3_finalize(pstmt);
        return -1;
    }
    sqlite3_finalize(pstmt);
    return 0;
}

static int executeWithQuery(sqlite3 *db,char ***result,int *col,const char *sql)
{
    int ret,row;

    ret = sqlite3_get_table(db,sql,result,&row,col,NULL);
    if(ret != SQLITE_OK)
    {
        return -1;
    }
    (*result)[(row+1)*(*col)] = NULL;

    return 0;
}

#if 0
static int _callback(void *NotUsed, int Argc, char **Argv, char **azColName)
{
    int i;

    for( i=0; i<Argc; i++)
    {
        SQL_DBG("%s = %s\n", azColName[i], Argv[i]? Argv[i]: "NULL");
    }
    SQL_DBG("\n");
    return 0;
}
#endif


static int _insert_device(zgw_device_t *device)
{
    int ret;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "insert into devices(name, mact, tag, ltt, mac, addr, sta, ott, ads, pid) values('unknown', %s, %d, %d, %d, %d, %d, %d, %d, %d);",
            device->mact, device->tag, device->mach, device->macl, device->addr, device->sta, 255, 1, 25000);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn,sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

static int _delete_device(zgw_device_t *device)
{
    int ret;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "delete from devices where ltt = %d and mac = %d;", device->mach, device->macl);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn,sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

/*
*	return: -1 error, 0: OK
*/
int sql_delete_one_item(char* tableName, char* ifTitleName, int ifValue, char* ifString)
{
    int ret;
    sqlite3 * conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    if (ifString == NULL)
    {
        snprintf(sql, MAX_SQL_LEN, "delete from %s where %s = %d;", tableName, ifTitleName, ifValue);
    }
    else
    {
        snprintf(sql, MAX_SQL_LEN, "delete from %s where %s = '%s';", tableName, ifTitleName, ifString);
    }

    SQL_DEBUG("sql: %s\n", sql);
    ret = executeNoQuery(conn, sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

int sql_update_integer_title(char* tableName, char* titleName, uint16 titleValue, int markId)
{
    int ret;
    sqlite3 * conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "update %s set %s = %d where id = %d;", tableName, titleName, titleValue, markId);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn, sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

/*
*	return: 0 OK, -1 OK
*/
int sql_update_one_item(char* tableName, char* upTitleName, int upValue,
                        char* ifTitleName, char* ifValue)
{
    int ret;
    sqlite3 * conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "update %s set %s = %d where %s = '%s';", tableName, upTitleName, upValue, ifTitleName, ifValue);

    SQL_DEBUG("sql: %s\n", sql);
    ret = executeNoQuery(conn, sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

/*
*	return: 0 OK, -1 NOK
*/
int sql_update(char* sql)
{
    int ret;
    sqlite3 * conn;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    SQL_DEBUG("sql: %s\n", sql);
    ret = executeNoQuery(conn, sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

/*
*	return: 0 OK , -1 ERROR
*	example:"insert into grouptask(tid,gid,devl,cfg,tsta) values('%s',%d,'%s',%d,%d);"
*/
static int insert_date_sql(char* sql)
{
    int ret;
    sqlite3 *conn;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn,sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

/*
*	Note: "select id,mac form devices where id = 1;"
*	select must two item, but return is second from select by DB
*	return: 0 ok, -1 error
*/
int sql_get_ont_item(char* sql, getDateType getType, int* getInt, char* getString)
{
    int ret, ncol = 0;
    sqlite3* conn;
    char** array;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

    ret = -1;
    if (array[ncol] != NULL)
    {
        if (getType == GET_INTEGER)
        {
            *getInt = atoi(CHECKOUT_PARA_NULL(array[ncol+1]));
            SQL_DEBUG("sql get integer: %d\n", *getInt);
        }
        else if (getType == GET_STRING)
        {
            if (getString != NULL)
            {
                strcpy(getString, CHECKOUT_PARA_NULL(array[ncol+1]));
                SQL_DEBUG("sql get string: %s\n", getString);
            }
        }

        ret = 0;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return ret;
}


/*
*	parameter type: char * buf;
*	parameter example: "select ltt, mac from devices where ltt=216469469 and mac=5465498654;"
*	return value: 0 exist, -1 no exist
*/
static int
_query_mark_exist_status(char* searchSql)
{
    int ret,ncol,notfind = -1;
    sqlite3 *conn;
    char **array;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    SQL_DBG("sql: %s\n", searchSql);
    ret = executeWithQuery(conn,&array,&ncol, searchSql);
    IF_SQL_ERR(ret,conn)

    if (array[ncol] != NULL)
    {
        // SQL_DBG("mac: %s, %s is already exist!\n",array[ncol], array[ncol+1]);
        notfind = 0;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return notfind;
}

/*
*	paremeter type: char * buf;
*	parameter example: "delete from devices where ltt = %d and mac = %d;"
*	return value:   0 successful, -1 error
*/
static int _query_delete_mark(char* searchSql)
{
    int ret;
    sqlite3 *conn;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    SQL_DBG("sql: %s\n", searchSql);
    ret = executeNoQuery(conn, searchSql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

/*
*	return: 0 exist, -1 not exist
*/
static int _query_device_withmac(unsigned int mach, unsigned int macl)
{
    int ret,ncol,notfind = -1;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char **array;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "select ltt, mac from devices where ltt=%d and mac=%d;", mach, macl);
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    if (array[ncol] != NULL)
    {
        SQL_DBG("mac: %s, %s is already exist!\n",array[ncol], array[ncol+1]);
        notfind = 0;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return notfind;
}


/*
*	return: 0 exist, -1 not exist
*/
static int _query_device_withaddr(unsigned short addr)
{
    int ret,ncol,notfind = -1;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char **array;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "select addr from devices where addr=%d;", addr);
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    if (array[ncol] != NULL)
    {
        SQL_DBG("addr: %s is already exist!\n",array[ncol]);
        notfind = 0;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return notfind;
}

/*
*	return: 0 exist, -1 not exist
*/
static int _query_device_withaddrtag(unsigned short addr, unsigned short tag)
{
    int ret,ncol,notfind = -1;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char **array;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "select tag from devices where addr=%d and tag=%d;", addr, tag);
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    if (array[ncol] != NULL)
    {
        SQL_DBG("addr(%d) & tag(%d) is already exist!\n",addr, tag);
        notfind = 0;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return notfind;
}


static int _query_scenes_lch(char *sname, unsigned char *lum, unsigned char *ct, unsigned char *hue)
{
    int ret,ncol;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char **array;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "select lum, ct, hue from groups where sta=44 and name = \'%s\';", sname);
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    if (array[ncol] != NULL)
    {
        *lum = atoi(array[ncol]);
        *ct = atoi(array[ncol+1]);
        *hue = atoi(array[ncol+2]);
        SQL_DBG("scene(%s): lum - %s, ct - %s, hue - %s \n", sname, array[ncol], array[ncol+1], array[ncol+2]);
        SQL_DBG("scene(%s): lum - %d, ct - %d, hue - %d \n", sname, *lum, *ct, *hue);
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}


unsigned int _query_device_uenh(void)
{
    int ret,ncol,i;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char **array;
    unsigned int temp = 0;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    sprintf(sql, "select count uenh from devices;");
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    i = ncol; //first row is key, row2... are values
    while(array[i] != NULL)
    {
        temp += atoi(array[i]);
        SQL_DBG("\narray[ %d ]: ", i/ncol);
        SQL_DBG("uenh: %s",array[i]);
        i+=ncol;
    }

    SQL_DBG("u32totaluenh: %d",temp);

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return temp;
}


unsigned int _query_device_uenl(void)
{
    int ret,ncol,i;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char **array;
    unsigned int temp = 0;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    sprintf(sql, "select count uenl from devices;");
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    i = ncol; //first row is key, row2... are values
    while(array[i] != NULL)
    {
        temp += atoi(array[i]);
        SQL_DBG("\narray[ %d ]: ", i/ncol);
        SQL_DBG("uenl: %s",array[i]);
        i+=ncol;
    }

    SQL_DBG("u32totaluenl: %d",temp);

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return temp;
}


unsigned short _query_device_watt(void)
{
    int ret,ncol,i;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char **array;
    unsigned short temp = 0;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    sprintf(sql, "select watt from devices;");
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    i = ncol; //first row is key, row2... are values
    while(array[i] != NULL)
    {
        temp = atoi(array[i]);
        SQL_DBG("\narray[ %d ]: ", i/ncol);
        SQL_DBG("uen: %s",array[i]);
        i+=ncol;
    }

    SQL_DBG("u32watt: %d",temp);

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return temp;
}


unsigned short _query_device_offh(unsigned short addr)
{
    int ret,ncol,i;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char **array;
    unsigned short temp = 0;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    snprintf(sql, MAX_SQL_LEN, "select offh from devices where addr=%d;", addr);
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    i = ncol; //first row is key, row2... are values
    while(array[i] != NULL)
    {
        temp = atoi(array[i]);
        SQL_DBG("\narray[ %d ]: ", i/ncol);
        SQL_DBG("offh: %s",array[i]);
        i+=ncol;
    }

    SQL_DBG("offh: %d",temp);

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return temp;
}


unsigned short _query_device_onh(unsigned short addr)
{
    int ret,ncol,i;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char **array;
    unsigned short temp = 0;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    snprintf(sql, MAX_SQL_LEN, "select onh from devices where addr=%d;", addr);
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    i = ncol; //first row is key, row2... are values
    while(array[i] != NULL)
    {
        temp = atoi(array[i]);
        SQL_DBG("\narray[ %d ]: ", i/ncol);
        SQL_DBG("onh: %s",array[i]);
        i+=ncol;
    }

    SQL_DBG("onh: %d",temp);

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return temp;
}


static int _check_wday(char *str, int wday)
{
    const char *split = ", ";
    char *p;
    int tmp, tmpwday, findflag = 0;

    tmpwday = (wday == 0)?(7):(wday);

    //SQL_DBG("parameter: %s, %d\n", str, tmpwday);

    p = strtok(str,split);
    while(p != NULL)
    {
        tmp = atoi(p);
        //SQL_DBG("str:%s, tmp:%d\n", p, tmp);
        if (tmp == tmpwday)
        {
            findflag = 1;
            break;
        }
        p = strtok(NULL, split);
    }

    return findflag;
}


static int _check_time(char *str, int hour, int min)
{
    const char *split = ":";
    char *p;
    int i, tmp = 0, totalmin, findflag = 0;

    SQL_DBG("parameter: %s, %d, %d\n", str, hour, min);

    i = 0;
    totalmin = hour * 60 + min;
    p = strtok(str,split);
    while(p != NULL)
    {
        //SQL_DBG("%d: str:%s, tmp:%d\n", i, p, atoi(p));
        if (i == 0)
        {
            tmp = atoi(p) * 60;
        }
        else
        {
            tmp += atoi(p);
        }
        p = strtok(NULL, split);
        i++;
        //SQL_DBG("tmp = %d\n", tmp);
    }

    SQL_DBG("totalmin:%d, tmp:%d\n", totalmin, tmp);
    if ((totalmin >= tmp) && (totalmin < tmp + 1))
    {
        findflag = 1;
    }

    return findflag;
}


static int _check_timer(char *wdaystr, char *tmstr)
{
    time_t now;
    struct tm *t;
    //char wdaystr[] = ", 1, 2, 3, 4, 6, 7";
    //char tmstr[] = "16:31";

    now = time(NULL);
    t = localtime(&now);
    SQL_DBG("TIME: %02d:%02d:%02d %2d\n", t->tm_hour, t->tm_min, t->tm_sec, t->tm_wday);

    if ((_check_wday(wdaystr, t->tm_wday) == 1) &&
            (_check_time(tmstr, t->tm_hour, t->tm_min) == 1))
    {
        SQL_DBG("timer: time arrived!\n");
        return 1;
    }

    return 0;
}


static int _timer_response(char *rids, char *snames)
{
    extern int sendHost2NodeMsg(teMsgType emsgType, uint8 *pu8MsgBuf, uint16 buf_len);

    typedef struct
    {
        unsigned short gid;
        unsigned char onf;
        unsigned char lum;
        unsigned char ct;
        unsigned char hue;
    } zgw_timerresponse_t;

    int i;
    zgw_timerresponse_t reslist[MAX_DEV_NUM];
    unsigned char resnum;

    const char *split = ",";
    char *p;

    i = 0;
    p = strtok(rids,split);
    while(p != NULL)
    {
        reslist[i].gid = atoi(p);
        p = strtok(NULL,split);
        i++;
    }
    resnum = i;

    i = 0;
    p = strtok(snames,split);
    while(p != NULL)
    {
        _query_scenes_lch(p, &reslist[i].lum, &reslist[i].ct, &reslist[i].hue);
        SQL_DBG("%s(%d, %d, %d)\n", p, reslist[i].lum, reslist[i].ct, reslist[i].hue);
        p = strtok(NULL,split);
        i++;
    }

    i = 0;
    do
    {
        unsigned char u8buf[3] = {0};
        u8buf[0] = (reslist[i].gid >> 8) & 0xFF;
        u8buf[1] = reslist[i].gid & 0xFF;
        u8buf[2] = reslist[i].lum;
        sendHost2NodeMsg(E_SL_MSG_MOVE_TO_LEVEL_ONOFF, u8buf, 3);
        u8buf[2] = reslist[i].ct;
        sendHost2NodeMsg(E_SL_MSG_MOVE_TO_COLOUR_TEMPERATURE, u8buf, 3);
        u8buf[2] = reslist[i].hue;
        sendHost2NodeMsg(E_SL_MSG_ENHANCED_MOVE_TO_HUE_SATURATION, u8buf, 3);
        SQL_DBG("id%d, %d, %d, %d, %d\n", i, reslist[i].gid, reslist[i].lum, reslist[i].ct, reslist[i].hue);
        i++;
    }
    while(i < resnum);

    return 0;
}

/*
*	return: 0 OK, -1 error
*/
int self_recovery_add_group(uint16 shortAddr, uint32 mach, uint32 macl)
{
    char sql[SQL_BUF_MAX] = "\0";
    char groupNumList[256] = "\0";
    char srcGroupNumList[256] = "\0";
    int notUse = 0;
    char delims[] = ",";
    char* p_getGroupNum = NULL;
    uint8 groupIndex = 0;
    char mact[32] = "\0";
    char tid[32] = "\0";

    memset(mact, '\0', 32);
    memset(tid, '\0', 32);
    snprintf(mact, 32, "%d%d", mach, macl);
    snprintf(tid, 32, ",%d%d", mach, macl);

    // 1. get self-recovery group number list
    memset(groupNumList, '\0', 256);
    memset(srcGroupNumList, '\0', 256);
    memset(sql, '\0', SQL_BUF_MAX);
    sprintf(sql, "select id,addgl from devices where mact = '%s';", mact);
    if (sql_get_ont_item(sql, GET_STRING, &notUse, groupNumList) == 0)
    {
        //2. IF self-recovery task start
        _DBG("Get groupnum list: %s\n", groupNumList);
        m_strncpy(srcGroupNumList, groupNumList, 256);
        p_getGroupNum = strtok(groupNumList, delims);
        if (p_getGroupNum != NULL)
        {
			// 3. insert add group task.(check task exist status)
            memset(sql, '\0', SQL_BUF_MAX);
            snprintf(sql, MAX_SQL_LEN, "select tid,gid from grouptask where tid = '%s';", tid);
            if (_query_mark_exist_status(sql) == 0) //exist, need delete this mark first.
            {
                sql_delete_one_item("grouptask", "tid", 0, tid);
            }

            memset(sql, '\0', SQL_BUF_MAX);
            snprintf(sql, MAX_SQL_LEN, "insert into grouptask(tid,gid,devl,cfg,tsta) values('%s',%d,'%s',%d,%d);"
                    ,tid, 0, srcGroupNumList, T_CTL_SELF_RECOVERY_ADD_GROUP, T_HANDLER_NOT_START);

            if (insert_date_sql(sql) != 0)
            {
                _DBG("[Self-recovery add task error.\n]");
                return -1;
            }
			_DBG("[Self-recovery add task successful.\n]");
			return 0;
					
        }
        _DBG("[Don`t need to Self-recovery.\n]");
        return 0;
    }
    return -1;
}

int sql_insert_check_device_task(uint16 shortAddr, uint32 mach, uint32 macl, char* groupNumList)
{
	char tid[32] = "\0";
	char sql[MAX_SQL_LEN] = "\0";
	char groupList[256] = "\0";
	char* p_getDate = NULL;
	char delims[] = ",";

	memset(groupList, '\0', 256);
	m_strncpy(groupList, groupNumList, 256);
	p_getDate = strtok(groupList, delims);
	if (p_getDate != NULL)
	{
		memset(tid, '\0', 32);
		snprintf(tid, 32, ",%d,%d,%d", shortAddr, mach, macl);
		
	    memset(sql, '\0', SQL_BUF_MAX);
	    snprintf(sql, SQL_BUF_MAX, "select tid,gid from grouptask where tid = '%s';", tid);
	    if (_query_mark_exist_status(sql) == 0) //exist, need delete this mark first.
	    {
	        sql_delete_one_item("grouptask", "tid", 0, tid);
	    }

	    memset(sql, '\0', SQL_BUF_MAX);
	    snprintf(sql, SQL_BUF_MAX, "insert into grouptask(tid,gid,devl,cfg,tsta) values('%s',%d,'%s',%d,%d);"
	            ,tid, 0, groupNumList, T_CTL_CHECK_DEVICE_GROUP_STATUS, T_HANDLER_NOT_START);

	    if (insert_date_sql(sql) != 0)
	    {
	        _DBG("[Check device add task error.\n]");
	        return -1;
	    }
	}

	return 0;
}

int sql_insert_device(zgw_device_t *device)
{
    int ret, ontUse;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = "\0";
	char groupNumList[256] = "\0";

    // add && mach && macl   all exist , then it exist.
    memset(sql, '\0', MAX_SQL_LEN);
	memset(groupNumList, '\0', 256);
    snprintf(sql, SQL_BUF_MAX, "select addr, addgl from devices where addr=%d and ltt=%d and mac=%d;"
		, device->addr, device->mach, device->macl);
	if (sql_get_ont_item(sql, GET_STRING, &ontUse, groupNumList) == 0)
	{
		// IF reset device but addr not change, we should self-recovery group
		SQL_DBG("Device is existed.(addr:%d, mach:%d, macl:%d)\n",
				device->addr, device->mach, device->macl);	
		sql_insert_check_device_task(device->addr, device->mach, device->macl, groupNumList);
		return 1;
	}

#if 0   
    if (_query_device_with_addr_mac(device->addr, device->mach, device->macl) == 0)
    {
        SQL_DBG("Device is existed.(addr:%d, mach:%d, macl:%d)\n",
                device->addr, device->mach, device->macl);	
        return 1;
    }
#endif

    // mach && macl && addr is not exist, and then insert device mark on DB.
    // if addr exist, but mach && macl is not exist on DB, we shoult delete last mark,
    // and then add
    if (_query_device_withmac(device->mach, device->macl) == -1)
    {
        if (_query_device_withaddr(device->addr) == 0)  // exist device
        {
            if (_query_delete_device_byaddr(device->addr) == 0)
            {
                _DBG("Insert front to delete DB src addr: %d.\n", device->addr);
            }
        }

        return _insert_device(device);
    }

    // if mach && macl is not exist, but addr exist, we shoult delete exist addr mark,and then update
    if (_query_device_withaddr(device->addr) == 0)
    {
        if (_query_delete_device_byaddr(device->addr) == 0)
        {
            _DBG("Update front to delete DB src addr: %d.\n", device->addr);
        }
    }

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    //update device's addr case it changes.
    memset(sql, '\0', MAX_SQL_LEN);
    //sprintf(sql, "update devices set addr = %d, ads = 1 where ltt = %d and mac = %d;", device->addr, device->mach, device->macl);
    snprintf(sql, SQL_BUF_MAX, "update devices set addr = %d, ott = 255, ads = 1 where ltt = %d and mac = %d;", device->addr, device->mach, device->macl);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn,sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)

    //Self recovery add group
    self_recovery_add_group(device->addr, device->mach, device->macl);
    return 0;
}

int sql_update_majorVersion(uint16 majorVersion, int markId)
{
    int ret;
    sqlite3 * conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, SQL_BUF_MAX, "update progress set nver = %d where id = %d;", majorVersion, markId);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn, sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

int sql_get_device_mach_and_macl(uint16 sAddr, uint32* mach, uint32* macl)
{
    int ret = -1, ncol = 0;
    sqlite3* conn;
    char** array;
    char sql[SQL_BUF_MAX] = "\0";

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', SQL_BUF_MAX);
    snprintf(sql, SQL_BUF_MAX, "select ltt,mac from devices where addr = %d;", sAddr);
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

    if (array[ncol] != NULL)
    {
        *mach = atoi(array[ncol]);
        *macl = atoi(array[ncol+1]);
        ret = 0;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return ret;
}

int sql_update_progressJN5169_status(int progressStatus, int markId)
{
    int ret;
    sqlite3 * conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, SQL_BUF_MAX, "update progress set psta = %d where id = %d;", progressStatus, markId);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn, sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

int sql_update_device(zgw_device_t *device)
{
    int ret;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char tmpstr[128] = {0};

    if (_query_device_withaddrtag(device->addr, device->tag) == 0)
    {
        return 0;
    }

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, SQL_BUF_MAX, "update devices set name = \'%s\'", device->name);

#if 0
    if (device->note[0] != '\0')
    {
        memset(tmpstr, '\0', 128);
        sprintf(tmpstr, "note = %s ", device->note);
        strcat(sql, tmpstr);
    }
#endif

    if (device->tag != 0xFFFF)
    {
        memset(tmpstr, '\0', 128);
        snprintf(tmpstr, 128, ", tag = %d", device->tag);
        strcat(sql, tmpstr);
    }

    if (device->sta != 0xFF)
    {
        memset(tmpstr, '\0', 128);
        snprintf(tmpstr, 128, ", sta = %d", device->sta);
        strcat(sql, tmpstr);
    }

    memset(tmpstr, '\0', 128);
    //sprintf(tmpstr, "where mac = %1d;", device->mac);
    snprintf(tmpstr, 128, " where addr = %d;", device->addr);
    strcat(sql, tmpstr);

    SQL_DBG("sql: %s\n", sql);

    ret = executeNoQuery(conn,sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

int sql_update_device_onoff(unsigned short addr, unsigned char onoff)
{
    int ret;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "update devices set onoff = %d, chs = 1 where addr = %d;", onoff, addr);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn,sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}


int sql_update_device_lum(unsigned short addr, unsigned char lum)
{
    int ret;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "update devices set lum = %d, chs = 1 where addr = %d;", lum, addr);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn,sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

int sql_update_device_ct(unsigned short addr, unsigned short ct)
{
    int ret;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "update devices set ct = %d, chs = 1 where addr = %d;", ct, addr);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn,sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}


int sql_update_device_hue(unsigned short addr, unsigned char hue)
{
    int ret;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "update devices set hue = %d, chs = 1 where addr = %d;", hue, addr);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn,sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}


int sql_update_device_lifetime(unsigned short addr, unsigned short onhour, unsigned short offhour)
{
#define COUNT_PER_HOUR    (120)

    int ret;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "update devices set onh = %d, offh = %d where addr = %d;", onhour, offhour, addr);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn,sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}


int sql_update_device_energy(unsigned short addr, unsigned int totaluseenergyh, unsigned int totaluseenergyl)
{
    int ret;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "update devices set uenh = %d, uenl = %d where addr = %d;", totaluseenergyh, totaluseenergyl, addr);

    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn,sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
    }


int sql_update_device_watt(unsigned short addr, unsigned short watt)
    {
    int ret;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "update devices set watt = %d where addr = %d;", watt, addr);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn,sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

int sql_update_device_ott(unsigned short addr, unsigned char ott)
{
    int ret;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "update devices set ott = %d where addr = %d;", ott, addr);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn,sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

int sql_delete_device(zgw_device_t *device)
{
    return _delete_device(device);
}

int sql_list_device(unsigned short *addrlist, unsigned short *deviceTaglist, unsigned int *num)
{
    int ret,ncol,i;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char **array;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    sprintf(sql, "select id, name, tag, mac, addr, sta from devices;");
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    i = ncol; //first row is key, row2... are values
    *num = 0;
    while(array[i] != NULL)
    {
    	deviceTaglist[*num] = atoi(CHECKOUT_PARA_NULL(array[i+2]));
        addrlist[*num] = atoi(CHECKOUT_PARA_NULL(array[i+4]));
		SQL_INFO("\narray[ %d ]:  id: %s, name: %s, tag: %s, mac: %s, addr: %s, (%d), sta: %s\n"
			, i/ncol, array[i], array[i+1], array[i+2], array[i+3], array[i+4], addrlist[*num], array[i+5]);
        i+=ncol;
        (*num)++;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}


int sql_query_device(unsigned short addr)
{
    return _query_device_withaddr(addr);
}

int sql_getUninitDevice(unsigned short *addr, unsigned int *mach, unsigned int *macl, unsigned short *tag)
{
    int ret,ncol;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char **array;

    *addr = 0;
    *mach = 0;
    *macl = 0;
    *tag = 0;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    sprintf(sql, "select addr, ltt, mac, tag from devices where ott=255 and tag<120;");
    SQL_DEBUG("sql: %s\n", sql);
    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    if (array[ncol] != NULL)
    {
        *addr = atoi(array[ncol]);
        *mach = atoi(array[ncol+1]);
        *macl = atoi(array[ncol+2]);
        *tag = atoi(array[ncol+3]);
        SQL_DBG("sql_getUninitDevice: addr: %d , mach %d , macl %d, tag %d!\n",*addr, *mach, *macl, *tag);
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)

    return (*addr == 0)?(1):(0);
}

/*
*	Note: get all data, we need to add id
*/
int sql_get_alldevice(char* devList)
{
    int ret = 0, ncol = 0;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char **array;
    uint8 i = 0;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    sprintf(sql, "select id, addr from devices;");
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    SQL_DBG("Device list: \n");
    i = ncol; //first row is key, row2... are values
    memset(devList, '\0', DEVICE_LIST_MAX);

    while (array[i] != NULL)
    {

        strcat(devList, ",");
        strcat(devList, CHECKOUT_PARA_NULL(array[i+1]));
        SQL_DBG(" %s\n", array[i+1]);
        i += ncol;
		ret = 1;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)

    return ret;
}

int sql_get_db_grouptask(dbGroupTaskParameter* groupTaskParameter)
{
    int ret = -1;
    int ncol = 0;
    sqlite3* conn;
    char sql[MAX_SQL_LEN] = {0};
    char** array;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    sprintf(sql, "select tid, gid, devl, cfg, tsta, errl from grouptask where tsta=1;");
    //SQL_DEBUG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

    memset(groupTaskParameter->p_taskId, '\0', GROUP_TASK_ID);
    memset(groupTaskParameter->p_deviceList, '\0', DEVICE_LIST_MAX);
    ret = -1;
    if (array[ncol] != NULL)
    {
        SQL_DBG("sql: %s\n", sql);
        m_strncpy(groupTaskParameter->p_taskId, CHECKOUT_PARA_NULL(array[ncol]), GROUP_TASK_ID);
        groupTaskParameter->groupId = (uint16)atoi(CHECKOUT_PARA_NULL(array[ncol+1]));
        m_strncpy(groupTaskParameter->p_deviceList, CHECKOUT_PARA_NULL(array[ncol+2]), DEVICE_LIST_MAX);
        groupTaskParameter->controlMethod = atoi(CHECKOUT_PARA_NULL(array[ncol+3]));
        groupTaskParameter->taskStatus = atoi(CHECKOUT_PARA_NULL(array[ncol+4]));
        SQL_DEBUG("Get Task: tid:%s, gid:%d, devList:%s, cfg:%d, tsta:%d\n",
               groupTaskParameter->p_taskId,
               groupTaskParameter->groupId,
               groupTaskParameter->p_deviceList,
               groupTaskParameter->controlMethod,
               groupTaskParameter->taskStatus);
        ret = 0;
        SQL_DBG("Init db group task successful.\n");
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)

    return ret;
}

int sql_get_groups_devlist(char* devList, int groupId)
{
    int ret, ncol = 0;
    sqlite3* conn;
    char sql[MAX_SQL_LEN] = {0};
    char** array;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "select dids from groups where gid = %d;", groupId);
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

    if (array[ncol] != NULL)
    {
        m_strncpy( devList, CHECKOUT_PARA_NULL(array[ncol]), DEVICE_LIST_MAX);
        SQL_DEBUG("sql get devList: %s\n", devList);
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

int sql_get_progress_status(int markId)
{
    int ret, ncol, progressStatus = 0;
    sqlite3 * conn;
    char sql[MAX_SQL_LEN] = {0};
    char ** array;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "select psta from progress where id = %d;", markId);
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

    progressStatus = 0;
    if (array[ncol] != NULL)
    {
        progressStatus = atoi(array[ncol]);
        SQL_DEBUG("progress status: %d\n", progressStatus);
    }
    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)

    return progressStatus;
}

int sql_query_timer(void)
{
    int ret,ncol,i;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char **array;

    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    sprintf(sql, "select onf, time, rt, rids, sids from timers;");
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    i = ncol; //first row is key, row2... are values
    while(array[i] != NULL)
    {
        SQL_DBG("\narray[ %d ]: onf(%s), time(%s), rt(%s), rids(%s), sids(%s) \n",
                i/ncol, array[i], array[i+1], array[i+2], array[i+3], array[i+4]);
        if (atoi(array[i]) == 0)
        {
            i+=ncol;
            continue;
        }
        if (_check_timer(array[i+2], array[i+1]) == 1)
        {
            _timer_response(array[i+3], array[i+4]);
        }
        i+=ncol;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    return 0;
}

int sql_insert_group(uint32 groupId, const char* devList)
{
    int ret;
    sqlite3 * conn;
    char sql[MAX_SQL_LEN] = {0};

    SQL_DEBUG("insert group:%d, devList:%s\n", groupId, devList);
    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    snprintf(sql, MAX_SQL_LEN, "insert into groups(gid,dids) values(%d,'%s');", groupId, devList);
    SQL_DEBUG("sql:%s\n", sql);
    ret = executeNoQuery(conn, sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

int sql_insert_mac(char *mac)
{
    int ret;
    sqlite3 *conn;
    char sql[SQL_BUF_MAX] = {0};

    SQL_DBG("mac: %s\n", mac);
    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', SQL_BUF_MAX);
    snprintf(sql, MAX_SQL_LEN, "insert into bindmac(mac) values('%s');", mac);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(conn,sql);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}


//table: app bind mac table
int sql_query_mac(char *mac)
{
    int ret,ncol,isbinded = 1;
    sqlite3 *conn;
    char **array;
    char sql[MAX_SQL_LEN] = {0};

    SQL_DBG("sql_query_mac - mac: %s\n", mac);

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "select id, mac from bindmac where mac='%s';", mac);
    SQL_DBG("sql: %s\n", sql);

    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    if (array[ncol] != NULL)
    {
        SQL_DBG("mac %s is binded in db\n", array[ncol+1]);
        isbinded = 0;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return isbinded;
}


/*
    param:pInMemory, pointer which point to the memory db
    param:zFilename, pointer which point to the file db direction
    param:isSave, 0-load data from file-db to memory-db; 1-save data from memory-db to file-db.
*/
int loadOrSaveDbInMemory(sqlite3 *pInMemeory, const char *zFilename, int isSave)
{
    int rc;
    sqlite3 *pFile;
    sqlite3_backup *pBackup;
    sqlite3 *pTo;
    sqlite3 *pFrom;

    ADD_LOCK(lockDB)
    rc = sqlite3_open(zFilename, &pFile);
    if(rc == SQLITE_OK)
    {
        pFrom = (isSave?pInMemeory:pFile);
        pTo = (isSave?pFile:pInMemeory);

        pBackup = sqlite3_backup_init(pTo,"main",pFrom,"main");

        if(pBackup)
        {
            (void)sqlite3_backup_step(pBackup,-1);
            (void)sqlite3_backup_finish(pBackup);
        }

        rc = sqlite3_errcode(pTo);
    }

    (void)sqlite3_close(pFile);
    FREE_LOCK(lockDB)
    return rc;
}


#if 0
int testmemroydb(void)
{
    int ret = 0;

    //char *filename = "d:\\test.db";
    sqlite3 *memoryDb;
    char sql[MAX_SQL_LEN] = {0};

    ret = sqlite3_open("memory:", &memoryDb);
    ret = loadOrSaveDbInMemory(memoryDb, ZGW_DB, 0);

    sprintf(sql, "update devices set onh = %d, offh = %d where addr = %d;", 0, 0, 6007);
    SQL_DBG("sql: %s\n", sql);
    ret = executeNoQuery(memoryDb,sql);

    ret = loadOrSaveDbInMemory(memoryDb, ZGW_DB, 1);

    sqlite3_close(memoryDb);

    return ret;
}
#endif

/*
    param flag: 0-init on boot, 1-save to flash, 2-load to tmp
*/
int loadOrSaveDbInTmp(int flag)
{
#define DB_INIT_TMP_DB 0
#define DB_SAVE_TO_FLASH 1
#define DB_LOAD_TO_TMP 2

    int rc = 0;
    sqlite3_backup *pBackup;
    sqlite3 *pTo;
    sqlite3 *pFrom;

    switch(flag)
    {
    case DB_INIT_TMP_DB:
    {
		system("chmod -R 777 /root/zgw.db");
        system("cp /root/zgw.db /tmp/zgw.db");
        system("chmod -R 777 /tmp/zgw.db");
    }
    break;
    case DB_SAVE_TO_FLASH:
    {
#define USE_SQLITE_BACKUP
#ifndef USE_SQLITE_BACKUP
        system("chmod -R 777 /root/zgw.db");
        system("cp /tmp/zgw.db /root/zgw.db");
#else
        ADD_LOCK(lockDB)
        rc = sqlite3_open(ZGW_DB, &pFrom);
        if(rc == SQLITE_OK)
        {
            rc = sqlite3_open(ZGW_DB_FLASH, &pTo);
            if(rc == SQLITE_OK)
            {
                pBackup = sqlite3_backup_init(pTo,"main",pFrom,"main");
                if(pBackup)
                {
                    (void)sqlite3_backup_step(pBackup,-1);
                    (void)sqlite3_backup_finish(pBackup);
                    SQL_DBG("OK of sqlite3_backup_finish !\n");
                }
                rc = sqlite3_errcode(pTo);
                SQL_DBG("sqlite3_errcode(%d) !\n", rc);
                (void)sqlite3_close(pTo);
            }
            (void)sqlite3_close(pFrom);
        }
        FREE_LOCK(lockDB)
#endif
    }
    break;
    case DB_LOAD_TO_TMP:
    {
        ADD_LOCK(lockDB)
        rc = sqlite3_open(ZGW_DB_FLASH, &pFrom);
        if(rc == SQLITE_OK)
        {
            rc = sqlite3_open(ZGW_DB, &pTo);
            if(rc == SQLITE_OK)
            {
                pBackup = sqlite3_backup_init(pTo,"main",pFrom,"main");
                if(pBackup)
                {
                    (void)sqlite3_backup_step(pBackup,-1);
                    (void)sqlite3_backup_finish(pBackup);
                }
                rc = sqlite3_errcode(pTo);
                (void)sqlite3_close(pTo);
            }
            (void)sqlite3_close(pFrom);
        }
        FREE_LOCK(lockDB)
    }
    break;
    default:
        break;
    }

    return rc;
}


int initDb(void)
{
    const char *createSQL = "create table if not exists bindmac (id integer PRIMARY KEY NOT NULL, mac varchar(12));";

    int ret;
    sqlite3 *conn;

    loadOrSaveDbInTmp(0);

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    ret = executeNoQuery(conn,createSQL);
    IF_SQL_ERR(ret,conn)

    sqlite3_close(conn);
    FREE_LOCK(lockDB)

    //testmemroydb();

    return 0;
}

static int _query_device_with_addr_mac(uint16 addr, uint32 mach, uint32 macl)
{
    char sql[MAX_SQL_LEN] = "\0";

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "select addr, ltt, mac from devices where addr=%d and ltt=%d and mac=%d;", addr, mach, macl);
    if (sql[0] != '\0')
    {
        return _query_mark_exist_status(sql);
    }
    return -1;
}

static int _query_delete_device_byaddr(uint16 addr)
{
    char sql[MAX_SQL_LEN] = "\0";

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "delete from devices where addr = %d;", addr);
    if (sql[0] != '\0')
    {
        return _query_delete_mark(sql);
    }
    return -1;
}

int sql_get_report_power(char* sendMsgBuf)
{
    int ret = 0;
    int ncol = 0;
    sqlite3* conn;
    char sql[MAX_SQL_LEN] = {0};
    char** array;
    uint16 i;
	char* p_getStringMD5 = NULL;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    sprintf(sql, "select ltt,mac,watt,uenl,onh,lqi,addgls from devices;");
    _DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

    //"{\"GMAC\":\"123456789\",\"LWEU\":[{\"MAC\":\"141235238832099\",\"WT\":150,\"EL\":5,\"UT\":120,\"LQI\":222,\"VER\":10}],\"md5\":\"12345678\"}"

    strcpy(sendMsgBuf, "{\"GMAC\":\"");
    strcat(sendMsgBuf, gMacId);
    strcat(sendMsgBuf, "\",\"LWEU\":[");

    ret = -1;
    i = ncol;
    while (array[i] != NULL)
    {
        if (i != ncol)
        {
            strcat(sendMsgBuf, ",");  // not first device mark.
        }

        strcat(sendMsgBuf, "{\"MAC\":\"");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i]));
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+1]));

        strcat(sendMsgBuf, "\",\"WT\":");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+2]));

        strcat(sendMsgBuf, ",\"EL\":");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+3]));

        strcat(sendMsgBuf, ",\"UT\":");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+4]));

        strcat(sendMsgBuf, ",\"LQI\":");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+5]));

		strcat(sendMsgBuf, ",\"VER\":");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+6]));
        strcat(sendMsgBuf, "}");

        i += ncol;
        ret = 0;
    }

	strcat(sendMsgBuf, "],");
	p_getStringMD5 = MD5_string(sendMsgBuf, 32);
    strcat(sendMsgBuf, "\"md5\":\"");
	strcat(sendMsgBuf, p_getStringMD5);
	strcat(sendMsgBuf, "\"}");
	FREE_APPLY_MEMORY(p_getStringMD5)
	
    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)

    return ret;
}

int sql_get_report_device_status(char* sendMsgBuf)
{
    int ret = 0;
    int ncol = 0;
    sqlite3* conn;
    char sql[MAX_SQL_LEN] = {0};
    char** array;
    uint16 i;
	char* p_getStringMD5 = NULL;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    sprintf(sql, "select ltt,mac,onoff,lum,ct,hue from devices where chs = 1;");
    SQL_DEBUG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

    //{"GMAC":"15467989988","LLCR":[{"MAC":"112348798","ONF":1,"LUM":150,"CCT":200,"RGB":150}],"md5":"12345678..."}

    strcpy(sendMsgBuf, "{\"GMAC\":\"");
    strcat(sendMsgBuf, gMacId);
    strcat(sendMsgBuf, "\",\"LLCR\":[");

    ret = -1;
    i = ncol;
    while (array[i] != NULL)
    {
        if (i != ncol)
        {
            strcat(sendMsgBuf, ",");  // not first device mark.
        }

        strcat(sendMsgBuf, "{\"MAC\":\"");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i]));
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+1]));

        strcat(sendMsgBuf, "\",\"ONF\":");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+2]));

        strcat(sendMsgBuf, ",\"LUM\":");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+3]));

        strcat(sendMsgBuf, ",\"CCT\":");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+4]));

        strcat(sendMsgBuf, ",\"RGB\":");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+5]));
        strcat(sendMsgBuf, "}");

        i += ncol;
        ret = 0;
    }

   // strcat(sendMsgBuf, "],\"md5\":\"12345678\"}");
   	strcat(sendMsgBuf, "],");
	p_getStringMD5 = MD5_string(sendMsgBuf, 32);
    strcat(sendMsgBuf, "\"md5\":\"");
	strcat(sendMsgBuf, p_getStringMD5);
	strcat(sendMsgBuf, "\"}");
	FREE_APPLY_MEMORY(p_getStringMD5)
	
    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)

    return ret;
}

int sql_get_report_new_device_list(char* sendMsgBuf)
{
    int ret = 0;
    int ncol = 0;
    sqlite3* conn;
    char sql[MAX_SQL_LEN] = {0};
    char** array;
    uint16 i;
	char* p_getStringMD5 = NULL;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    sprintf(sql, "select tag,addr,ltt,mac from devices where ads = 1;");
    _DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

    //{"GMAC":"1213549879","LTSM":[{"TY":63,"SADR":"40523","MAC":"213215496"}],"md5":"12345678..."}

    strcpy(sendMsgBuf, "{\"GMAC\":\"");
    strcat(sendMsgBuf, gMacId);
    strcat(sendMsgBuf, "\",\"LTSM\":[");

    ret = -1;
    i = ncol;
    while (array[i] != NULL)
    {
        if (i != ncol)
        {
            strcat(sendMsgBuf, ",");  // not first device mark.
        }

        strcat(sendMsgBuf, "{\"TY\":");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i]));

        strcat(sendMsgBuf, ",\"SADR\":\"");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+1]));

        strcat(sendMsgBuf, "\",\"MAC\":\"");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+2]));
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+3]));
        strcat(sendMsgBuf, "\"}");

        i += ncol;
        ret = 0;
    }

    //strcat(sendMsgBuf, "],\"md5\":\"12345678\"}");
    strcat(sendMsgBuf, "],");
	p_getStringMD5 = MD5_string(sendMsgBuf, 32);
    strcat(sendMsgBuf, "\"md5\":\"");
	strcat(sendMsgBuf, p_getStringMD5);
	strcat(sendMsgBuf, "\"}");
	FREE_APPLY_MEMORY(p_getStringMD5)
	
    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)

    return ret;
}

int sql_get_abnormal_device_list(char* sendMsgBuf)
{
	int ret = 0;
    int ncol = 0;
    sqlite3* conn;
    char sql[MAX_SQL_LEN] = {0};
    char** array;
    uint16 i;
	char* p_getStringMD5 = NULL;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    sprintf(sql, "select id,tag,ltt,mac,watt,pid from devices where uid = 1;");
    //_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

    /*
	* {"GMAC":"15467989988","ALARM":[{"MAC":"112348798","ED":1,"WT":150},{"MAC":"112348798","ED":1,"WT":150}],"md5":"12345678..."}
	*/

    strcpy(sendMsgBuf, "{\"GMAC\":\"");
    strcat(sendMsgBuf, gMacId);
    strcat(sendMsgBuf, "\",\"ALARM\":[");

    ret = -1;
    i = ncol;
    while (array[i] != NULL)
    {
        if (i != ncol)
        {
            strcat(sendMsgBuf, ",");  // not first device mark.
        }

		_DBG("tag: %d\n", atoi(CHECKOUT_REPORT_DATE(array[i+1])));
		if (atoi(CHECKOUT_REPORT_DATE(array[i+1])) == 65)	/* must device is plug can add list */
		{
			strcat(sendMsgBuf, "{\"MAC\":\"");
	        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+2]));
	        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+3]));
			
			strcat(sendMsgBuf, "\",\"ED\":");
	        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+5]));

	        strcat(sendMsgBuf, ",\"WT\":");
	        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+4]));
	        strcat(sendMsgBuf, "}");

			ret = 0; /* Have plug alarm */
		}

        i += ncol;
    }

    //strcat(sendMsgBuf, "],\"md5\":\"12345678\"}");
    strcat(sendMsgBuf, "],");
	p_getStringMD5 = MD5_string(sendMsgBuf, 32);
    strcat(sendMsgBuf, "\"md5\":\"");
	strcat(sendMsgBuf, p_getStringMD5);
	strcat(sendMsgBuf, "\"}");
	FREE_APPLY_MEMORY(p_getStringMD5)
	
    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)

    return ret;
}

int sql_get_report_ip_and_port(resportMsg* repMsg)
{
    int ret = 0;
    int ncol = 0;
    sqlite3* conn;
    char sql[MAX_SQL_LEN] = {0};
    char** array;
    uint16 i;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    strcpy(sql, "select id,sip,sport from report where id = 1;");
    //SQL_DEBUG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

    ret = -1;
    if (array[ncol] != NULL)
    {
        memset(repMsg->serverIp, '\0', SIZE_16BYTE);
        m_strncpy(repMsg->serverIp, CHECKOUT_PARA_NULL(array[ncol+1]), SIZE_16BYTE);
        repMsg->serverPort = CHECKOUT_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[ncol+2])));
        ret = 0;
    }
    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)

    return ret;
}

int sql_get_report_time_switch(resportMsg* repMsg)
{
    memset(repMsg->serverIp, '\0', SIZE_16BYTE);
    int ret = 0;
    int ncol = 0;
    sqlite3* conn;
    char sql[MAX_SQL_LEN] = {0};
    char** array;
    uint16 i;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    snprintf(sql, MAX_SQL_LEN, "select %s,%s,sip,sport from report where id = 1;", repMsg->searchTimeTitleName, repMsg->searchSwitchTitleName);
    SQL_DEBUG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

    ret = -1;
    if (array[ncol] != NULL)
    {
        memset(repMsg->serverIp, '\0', SIZE_16BYTE);
        repMsg->rpTime = CHECKOUT_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[ncol])));
        repMsg->rpSwitch = CHECKOUT_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[ncol+1])));
        m_strncpy(repMsg->serverIp, CHECKOUT_PARA_NULL(array[ncol+2]), SIZE_16BYTE);
        repMsg->serverPort = CHECKOUT_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[ncol+3])));
        ret = 0;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)

    return ret;
}

int sql_reset_report_flag(uint8 reportType, char* getDeviceMacAddr)
{
    char sql[SQL_BUF_MAX] = "\0";
    memset(sql, '\0', SQL_BUF_MAX);

    if (reportType == 1)
    {
        snprintf(sql, MAX_SQL_LEN, "update devices set chs = 0 where mact = '%s';", getDeviceMacAddr);
    }
    else if (reportType == 2)
    {
        snprintf(sql, MAX_SQL_LEN, "update devices set ads = 0 where mact = '%s';", getDeviceMacAddr);
    }
	else if (reportType == 3)
    {
        snprintf(sql, MAX_SQL_LEN, "update devices set uid = 0 where mact = '%s';", getDeviceMacAddr);
    }
	
    _DBG("sql:%s\n", sql);
    return sql_update(sql);
}


int sql_update_gmacid(char* newGMacId)
{
    char sql[SQL_BUF_MAX] = "\0";

    if (newGMacId == NULL)
    {
        return -1;
    }

    memset(sql, '\0', SQL_BUF_MAX);
    snprintf(sql, SQL_BUF_MAX, "update report set gmacid = '%s' where id = 1;", newGMacId);
    if (sql_update(sql) == 0)
    {
        memset(gMacId, '\0', 128);
        m_strncpy(gMacId, newGMacId, 128);
        return 0;
    }
    return -1;
}

/*
*	Note: get all data, we need to add id
*/
static char* get_all_device_json(char* sendMsgBuf, char** array, int ncol)
{
    //{"GMAC":"1654989849","LTSM":[
    //{"TY":63,"SADR":"40523","MAC":"213215496","LQI":50}
    //,{"TY":64,"SADR":"40523","MAC":"213215496","LQI":60}
    //]}
    //int ret = -1;
    
    int i = ncol;

    strcat(sendMsgBuf, "\",\"LTSM\":[");
    while (array[i] != NULL)
    {
        NOT_FIRST_JSON_OBJECT(sendMsgBuf,i)
        strcat(sendMsgBuf, "{\"TY\":");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+1]));
        strcat(sendMsgBuf, ",\"SADR\":\"");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+2]));
        strcat(sendMsgBuf, "\",\"MAC\":\"");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+3]));
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+4]));
		strcat(sendMsgBuf, "\",\"NA\":\"");
		strcat(sendMsgBuf, CHECKOUT_PARA_NULL(array[i+5]));
        strcat(sendMsgBuf, "\",\"LQI\":");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+6]));
		strcat(sendMsgBuf, ",\"VER\":");
        strcat(sendMsgBuf, CHECKOUT_REPORT_DATE(array[i+7]));
        strcat(sendMsgBuf, "}");

        i += ncol;
    }
    strcat(sendMsgBuf, "],\"md5\":\"12345678\"}");
    return sendMsgBuf;
}

static char* get_task_run_status(char* sendMsgBuf, char** array, int ncol)
{
    //{\"GMAC\":\"1654989849\",\"TSTA\":3,\"ERRL\":\",12345,23567\"}
    if (array[ncol] != NULL)
    {
        strcat(sendMsgBuf, "\",\"TSTA\":");
        strcat(sendMsgBuf, CHECKOUT_PARA_NULL(array[ncol]));

        strcat(sendMsgBuf, ",\"ERRL\":\"");
        strcat(sendMsgBuf, CHECKOUT_PARA_NULL(array[ncol+1]));
        strcat(sendMsgBuf, "\"}");
    }
    else
    {
        strcat(sendMsgBuf, "\",\"TSTA\":4,\"ERRL\":\"\"}");
    }

    return sendMsgBuf;
}

static char* get_http_json(char* sendMsgBuf, char** array, int ncol, httpRequestType requestType)
{
    strcpy(sendMsgBuf, "{\"GMAC\":\"");
    strcat(sendMsgBuf, gMacId);

    switch (requestType)
    {
    case REQUEST_ALL_DEVICE_JSON:
        get_all_device_json(sendMsgBuf, array, ncol);
        break;
    case REQUEST_TASK_STATUS:
        get_task_run_status(sendMsgBuf, array, ncol);
        break;
    default:
        break;
    }
    return sendMsgBuf;
}

int sql_http_request_json_data(char* sendMsgBuf, char* sql, httpRequestType requestType)
{
    int ret = 0;
    int ncol = 0;
    sqlite3* conn;
    char** array;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    _DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

    get_http_json(sendMsgBuf, array, ncol, requestType);
    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return 0;
}

int sql_update_report_msg(httpRequestMsg* httpMsg)
{
    char sql[SQL_BUF_MAX] = "\0";
    int ret = 0;

	extern void socket_update_report_tk(const char* updateTkBuf);

#if 0
    memset(sql, '\0', SQL_BUF_MAX);
    sprintf(sql, "select id,tk from report where gmacid = '0';");
    if (_query_mark_exist_status(sql) == 0) // The server first find the gw
    {
        _DBG("First get gmacid: %s\n", httpMsg->reportMsg.gMacId);
        memset(sql, '\0', SQL_BUF_MAX);
        sprintf(sql, "update report set gmacid = '%s', sip = '%s', sport = %d, tk = '%s' where id = 1;"
                ,httpMsg->reportMsg.gMacId, httpMsg->reportMsg.cloudServerIP
                , httpMsg->reportMsg.cloudServerPort, httpMsg->tk);

        memset(gMacId, '\0', 128);
        strcpy(gMacId, httpMsg->reportMsg.gMacId);
		// save DB
		
    }
    else
    {
        memset(sql, '\0', SQL_BUF_MAX);
        sprintf(sql, "update report set sip = '%s', sport = %d, tk = '%s' where id = 1;"
                , httpMsg->reportMsg.cloudServerIP
                , httpMsg->reportMsg.cloudServerPort, httpMsg->tk);
    }
#endif

	memset(sql, '\0', SQL_BUF_MAX);
    snprintf(sql, SQL_BUF_MAX, "update report set gmacid = '%s', sip = '%s', sport = %d, tk = '%s' where id = 1;"
            ,httpMsg->reportMsg.gMacId, httpMsg->reportMsg.cloudServerIP
            , httpMsg->reportMsg.cloudServerPort, httpMsg->tk);

    memset(gMacId, '\0', 128);
	if (httpMsg->reportMsg.gMacId != NULL)
	{
		m_strncpy(gMacId, httpMsg->reportMsg.gMacId, 128);
	}
    
	socket_update_report_tk(httpMsg->tk);   // update report to server tk value

    ret = sql_update(sql);
	
    return ret;
}


/*
*	return: 0: ok,  -1:NOK
*/
emReturnStatus init_gmacid(void)
{
    int notUseing;
    char sql[SQL_BUF_MAX] = "\0";

    memset(gMacId, '\0', 128);
    memset(sql, '\0', SQL_BUF_MAX);
    snprintf(sql, SQL_BUF_MAX ,"select id,gmacid from report where id = 1;");
    if( sql_get_ont_item(sql, GET_STRING, &notUseing, gMacId) == 0)
    {
        _DBG("init gMacId [%s] ok.\n", gMacId);
        return RE_SUCCESSFUL;
    }
    _DBG("init gMacId error.\n");
    return RE_ERROR;
}

void get_gmacid(char* gmacid)
{
    if (gmacid != NULL)
    {
        strcpy(gmacid, gMacId);
    }
}

/*
*	return : -1 error, >=1 insert count
*/
int sql_insert_group_task(httpRequestMsg* httpMsg)
{
    char sql[SQL_BUF_MAX] = "\0";
    //int ret = 0;

    memset(sql, '\0', SQL_BUF_MAX);
    snprintf(sql, SQL_BUF_MAX, "select id,gid from groups where gid = %d;", httpMsg->groupNum);
    if (_query_mark_exist_status(sql) == 0) //insert update group
    {
        memset(sql, '\0', SQL_BUF_MAX);
        snprintf(sql, SQL_BUF_MAX, "insert into grouptask(tid,gid,devl,cfg,tsta) values('%s',%d,'%s',%d,%d);"
                ,httpMsg->p_taskId, httpMsg->groupNum, httpMsg->p_deviceShortAddrList
                , T_CTL_UPDATE, T_HANDLER_NOT_START);
    }
    else  // insert add group
    {
        memset(sql, '\0', SQL_BUF_MAX);
        snprintf(sql, SQL_BUF_MAX, "insert into grouptask(tid,gid,devl,cfg,tsta) values('%s',%d,'%s',%d,%d);"
                ,httpMsg->p_taskId, httpMsg->groupNum, httpMsg->p_deviceShortAddrList
                , T_CTL_ADD, T_HANDLER_NOT_START);
    }

    return insert_date_sql(sql);
}

/*
*	return: 0 success find mac, -1 not find mac, 1 not exist device
*/
int sql_check_and_get_device_exist_status(httpRequestMsg* httpMsg)
{
    char sql[SQL_BUF_MAX] = "\0";
    uint32 mach, macl;

    memset(sql, '\0', SQL_BUF_MAX);
    snprintf(sql, SQL_BUF_MAX, "select id,addr from devices where addr = %d;", httpMsg->devPara.sAddr);
    if (_query_mark_exist_status(sql) == 0) //exist
    {
        if (sql_get_device_mach_and_macl(httpMsg->devPara.sAddr, &mach, &macl) == 0)
        {
            httpMsg->devPara.mach = mach;
            httpMsg->devPara.macl = macl;
            return 0;
        }
		else
		{
			return -1;
		}
    }
    return 1;
}

/*
*	return : -1 error, >=1 insert count
*/
int sql_insert_delete_group_task(httpRequestMsg* httpMsg)
{
    char sql[SQL_BUF_MAX] = "\0";

    memset(sql, '\0', SQL_BUF_MAX);
    snprintf(sql, SQL_BUF_MAX, "insert into grouptask(tid,gid,cfg,tsta) values('%s',%d,%d,%d);",
            httpMsg->p_taskId, httpMsg->groupNum, T_CTL_DELETE, T_HANDLER_NOT_START);
    return insert_date_sql(sql);
}

/*
*	return: -1 error, 0: OK
*/
int sql_delete_task_mark(httpRequestMsg* httpMsg)
{
    return sql_delete_one_item("grouptask", "tid", 0, httpMsg->p_taskId);
}

/*
*	return: -1 error, 0 OK
*/
int sql_update_task_run_status(httpRequestMsg* httpMsg)
{
    char sql[SQL_BUF_MAX] = "\0";

    memset(sql, '\0', SQL_BUF_MAX);
    snprintf(sql, SQL_BUF_MAX, "update grouptask set tsta = %d where tid = '%s';"
            , httpMsg->statusValue, httpMsg->p_taskId);
    return sql_update(sql);
}


int sql_add_get_device_lqi_task(httpRequestMsg* httpMsg)
{
    char sql[SQL_BUF_MAX] = "\0";
	taskControlMethod handlerId;

	switch (httpMsg->msgHead)
	{
		case 1017: handlerId = T_CTL_GET_ONE_DEVICE_LQI_STATUS;		break;
		case 5005: handlerId = T_CTL_GET_DEVICE_CURRENT_VERSION;	break;

		default: _DBG("add task error!!! [%s][%d]\n", __FUNCTION__, __LINE__);
		return 0;
	}

    memset(sql, '\0', SQL_BUF_MAX);
    snprintf(sql, SQL_BUF_MAX, "insert into grouptask(tid,devl,cfg,tsta) values('%s','%s',%d,%d);",
            httpMsg->p_taskId, httpMsg->p_deviceShortAddrList, handlerId, T_HANDLER_NOT_START);

    return insert_date_sql(sql);
}




/*
*	return: -1 error, 0 OK
*/
int sql_get_all_ltt_and_mac(char** mach, char** macl, char** idArray, int* count)
{
    int ret,ncol;
    sqlite3 *conn;
    char sql[MAX_SQL_LEN] = {0};
    char **array;
    int i = 0;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_SQL_ERR(ret,conn)

    memset(sql, '\0', MAX_SQL_LEN);
    strcpy(sql, "select id,ltt,mac,lqi from devices;");
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn,&array,&ncol,sql);
    IF_SQL_ERR(ret,conn)

    i = ncol;
    ret = -1;
    *count = 0;
    while (array[i] != NULL)
    {
        idArray[*count] = NULL;
        idArray[*count] = (char*)malloc(16);
        if (idArray[*count] == NULL)
        {
            continue;
        }
        mach[*count] = NULL;
        mach[*count] = (char*)malloc(16);
        if (mach[*count] == NULL)
        {
            continue;
        }

        macl[*count] = NULL;
        macl[*count] = (char*)malloc(16);
        if (macl[*count] == NULL)
        {
            continue;
        }

        m_strncpy(idArray[*count], CHECKOUT_PARA_NULL(array[i]), 16);
        m_strncpy(mach[*count], CHECKOUT_PARA_NULL(array[i+1]), 16);
        m_strncpy(macl[*count], CHECKOUT_PARA_NULL(array[i+2]), 16);
        _DBG("id:%s, mach:%s, macl:%s.\n", idArray[*count], mach[*count], macl[*count]);

        *count = *count + 1;
        i += ncol;
        ret = 0;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)

    return ret;
}

int sql_update_all_ltt_and_mac(void)
{
    char* mach[512];
    char* macl[512];
    char* idArray[512];
    char sql[MAX_SQL_LEN] = {0};
    int i = 0;
    int count = 0;

    sql_get_all_ltt_and_mac(mach, macl, idArray, &count);
    for (i = 0; i < count; i++)
    {
        if (mach[i] != NULL && macl[i] != NULL && idArray[i] != NULL)
        {
            memset(sql, '\0', MAX_SQL_LEN);
            snprintf(sql, SQL_BUF_MAX, "update devices set mact = '%s%s' where id = %d;", mach[i], macl[i], atoi(idArray[i]));
            sql_update(sql);
        }
        if (mach[i] != NULL) free(mach[i]);
        if (macl[i] != NULL) free(macl[i]);
        if (idArray[i] != NULL) free(idArray[i]);
    }

    return 0;
}

/*
*	Function: strcat add group mark to addgl
*	return: -1 NOK, 0 OK
*/
int sql_add_group_mark_to_devices(uint16 groupNum, char* deviceMac)
{
    char* sql = NULL;
    int notUse = 0;
    char* devAddGroupList = NULL;
    char* devDstGroupList = NULL;
    char groupNumString[16] = "\0";
    char delims[] = ",";
    char* p_getGroupNum = NULL;
    uint8 addFlag = 0;
	int ret = -1;

	APPLY_MEMORY_AND_CHECK(sql,SQL_BUF_MAX)
	APPLY_MEMORY_AND_CHECK(devAddGroupList,SQL_BUF_MAX)
	APPLY_MEMORY_AND_CHECK(devDstGroupList,SQL_BUF_MAX)

    // 1. get src device mark
    memset(sql, '\0', SQL_BUF_MAX);
    memset(devAddGroupList, '\0', SQL_BUF_MAX);
    memset(devDstGroupList, '\0', SQL_BUF_MAX);
    snprintf(sql, SQL_BUF_MAX, "select id,addgl from devices where mact = '%s';", deviceMac);
//	sprintf(sql, "select id,gmacid from report where id = 1;");
    if (sql_get_ont_item(sql, GET_STRING, &notUse, devAddGroupList) == 0)
    {
        // 2. IF addgl is NULL.(NULL is strcpy, not is strcat)

        memset(groupNumString, '\0', 16);
        sprintf(groupNumString, "%d", groupNum);

        p_getGroupNum = strtok(devAddGroupList, delims);
        if (p_getGroupNum != NULL)
        {
            do
            {
                if (strcmp(p_getGroupNum, groupNumString) == 0)
                {
                    addFlag = 1;
                }

                strcat(devDstGroupList, ",");
                strcat(devDstGroupList, p_getGroupNum);
                p_getGroupNum = strtok(NULL, delims);
            }
            while (p_getGroupNum != NULL);

            if (addFlag == 0)  // add new group number
            {
                strcat(devDstGroupList, ",");
                strcat(devDstGroupList, groupNumString);
            }

        }
        else
        {
            strcat(devDstGroupList, ",");
            strcat(devDstGroupList, groupNumString);
        }


    }

    // 3. update the device addgl
    memset(sql, '\0', SQL_BUF_MAX);
    snprintf(sql, SQL_BUF_MAX, "update devices set addgl = '%s' where mact = '%s';", devDstGroupList, deviceMac);
	ret = sql_update(sql);
	
	FREE_APPLY_MEMORY(sql)
	FREE_APPLY_MEMORY(devAddGroupList)
	FREE_APPLY_MEMORY(devDstGroupList)
	
    return ret;
}

/*
*	return : -1 NOK, 0 OK
*/
int sql_delete_group_mark_to_devices(uint16 groupNum, char* deviceMac)
{
    char* sql = NULL;
    int notUse = 0;
    char* devSrcGroupList = NULL;
    char* devDstGroupList = NULL;
    char groupNumString[16] = "\0";
    char delims[] = ",";
    char* p_getGroupNum = NULL;
	int ret = -1;

	APPLY_MEMORY_AND_CHECK(sql,SQL_BUF_MAX)
	APPLY_MEMORY_AND_CHECK(devSrcGroupList,SQL_BUF_MAX)
	APPLY_MEMORY_AND_CHECK(devDstGroupList,SQL_BUF_MAX)

    // 1. get src device mark
    memset(groupNumString, '\0', 16);
    sprintf(groupNumString, "%d", groupNum);

    memset(devSrcGroupList, '\0', SQL_BUF_MAX);
    memset(devDstGroupList, '\0', SQL_BUF_MAX);

    memset(sql, '\0', SQL_BUF_MAX);
    snprintf(sql, SQL_BUF_MAX, "select id,addgl from devices where mact = '%s';", deviceMac);
    if (sql_get_ont_item(sql, GET_STRING, &notUse, devSrcGroupList) == 0)
    {
        // 2. analysis and delete group num
        p_getGroupNum = strtok(devSrcGroupList, delims);
        while (p_getGroupNum != NULL)
        {
            if (strcmp(p_getGroupNum, groupNumString) == 0)
            {
                p_getGroupNum = strtok(NULL, delims);
                continue;
            }

            strcat(devDstGroupList, ",");
            strcat(devDstGroupList, p_getGroupNum);
            p_getGroupNum = strtok(NULL, delims);
        }

        // 3. update the device addgl
        memset(sql, '\0', SQL_BUF_MAX);
        snprintf(sql, SQL_BUF_MAX, "update devices set addgl = '%s' where mact = '%s';", devDstGroupList, deviceMac);

		ret = sql_update(sql);
    }

	FREE_APPLY_MEMORY(sql)
	FREE_APPLY_MEMORY(devSrcGroupList)
	FREE_APPLY_MEMORY(devDstGroupList)

    return ret;
}

int sql_check_MT7688_update_JN5169_status(void)
{
	char sql[SQL_BUF_MAX] = "\0";
	int progressStatus = 0;

	memset(sql, '\0', SQL_BUF_MAX);
	strcpy(sql, "select id,pros from progress where id = 1;");
	if (sql_get_ont_item(sql, GET_INTEGER, &progressStatus, NULL) == 0)
	{
		return progressStatus;
	}
	else
	{
		return -1;
	}
}


/*
*	return: 0 OK, -1 NOK
*/
int sql_successful_progress_JN5169(int updateMajorVersion)
{
	char sql[SQL_BUF_MAX] = "\0";

	memset(sql, '\0', SQL_BUF_MAX);
	snprintf(sql, SQL_BUF_MAX, "update progress set over = %d, pros = 1 where id = 1;", updateMajorVersion);
	return sql_update(sql);
}

/*
*	return: 0 OK, -1 NOK
*/
int sql_update_report_parameter(httpRequestMsg * httpMsg)
{
	char sql[SQL_BUF_MAX] = "\0";

	memset(sql, '\0', SQL_BUF_MAX);
	snprintf(sql, SQL_BUF_MAX, "update report set powt = %d, pows = %d, devt = %d, devs = %d, ndevt = %d, ndevs = %d where id = 1;"
			, CHECKOUT_GREATER_THAN_ZERO(httpMsg->reportMsg.powerTime)
			, CHECKOUT_GREATER_THAN_ZERO(httpMsg->reportMsg.powerSwitch)
			, CHECKOUT_GREATER_THAN_ZERO(httpMsg->reportMsg.deviceStatusTime)
			, CHECKOUT_GREATER_THAN_ZERO(httpMsg->reportMsg.deviceStatusSwitch)
			, CHECKOUT_GREATER_THAN_ZERO(httpMsg->reportMsg.addDeviceTime)
			, CHECKOUT_GREATER_THAN_ZERO(httpMsg->reportMsg.addDeviceSwitch));
	return sql_update(sql);
}

/*
*	return: 0 OK, -1 NOK
*/
int sql_start_MT7688_update_JN5169(void)
{
	char sql[SQL_BUF_MAX] = "\0";

	memset(sql, '\0', SQL_BUF_MAX);
	strcpy(sql, "update progress set psta = 1 where id = 1;");
	return sql_update(sql);
}

/*
* 	return:  -1 NOK, 1 OK
*/
int sql_get_MT7688_and_JN5169_version_time(uint32* p_getMT7688VersionTime
															, uint32* p_getJN5169VersionTime)
{
	int ret, ncol = 0;
    sqlite3* conn;
    char** array;
	char sql[SQL_BUF_MAX] = "\0";

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

	memset(sql, '\0', SQL_BUF_MAX);
	strcpy(sql, "select id,mtt,jnt from progress where id = 1;");
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

    ret = -1;
    if (array[ncol] != NULL)
    {
        *p_getMT7688VersionTime = CHECKOUT_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[ncol+1])));
		*p_getJN5169VersionTime = CHECKOUT_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[ncol+2])));

        ret = 0;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return ret;
}

int sql_update_progress_MT7688_version(uint32 newVersion)
{
	char sql[SQL_BUF_MAX] = "\0";

	memset(sql, '\0', SQL_BUF_MAX);
	sprintf(sql, "update progress set gwver = %d where id = 1;", newVersion);
	return sql_update(sql);
}

/*
*	return: 0 need to update , -1 not need to update
*/
int sql_check_MT7688_version(uint32 MT7688Version)
{
	char sql[SQL_BUF_MAX] = "\0";
	uint32 getMT7688Version = 0;

	memset(sql, '\0', SQL_BUF_MAX);
	strcpy(sql, "select id,gwver from progress where id = 1;");
	if (sql_get_ont_item(sql, GET_INTEGER, &getMT7688Version, NULL) == 0)
	{
		_DBG("SQL VERSION: %d, request version: %d\n", getMT7688Version, MT7688Version);
		return ((MT7688Version == getMT7688Version) ? -1 : 0);
	}
	else
	{
		return -1;
	}
}


/*
*	return: 0 OK, -1 NOK
*/
int sql_modify_gateway_update_request_time(httpRequestMsg* httpMsg)
{
	char sql[SQL_BUF_MAX] = "\0";

	memset(sql, '\0', SQL_BUF_MAX);
	snprintf(sql, SQL_BUF_MAX, "update progress set mtt = %d, jnt = %d where id = 1;"
				, httpMsg->gatewayVersion.mt7688Version, httpMsg->gatewayVersion.jn5169Version);
	return sql_update(sql);
}

/*
*	return: 0 OK, -1 NOK
*/
int sql_get_gateway_chip_version(uint32* f_getMT7688Version, uint32* f_getJN5169Version)
{
	int ret, ncol = 0;
    sqlite3* conn;
    char** array;
	char sql[SQL_BUF_MAX] = "\0";

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

	memset(sql, '\0', SQL_BUF_MAX);
	strcpy(sql, "select id,nver,gwver from progress where id = 1;");
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

    ret = -1;
    if (array[ncol] != NULL)
    {
        *f_getJN5169Version = CHECKOUT_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[ncol+1])));
		*f_getMT7688Version = CHECKOUT_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[ncol+2])));

        ret = 0;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return ret;
}

int sql_init_report_tk_buffer(char* tkBuf)
{
	char sql[SQL_BUF_MAX] = "\0";
	int notUse = 0;

	memset(tkBuf, '\0', 256);
	memset(sql, '\0', SQL_BUF_MAX);
	strcpy(sql, "select id,tk from report where id = 1;");
	return sql_get_ont_item(sql, GET_STRING, &notUse, tkBuf);
}


// get porgress id == 2, IF not exist -> insert, else update
// return: 0 OK		-1 error
int sql_set_JN5169_clear_E2ROM(int _clearE2ROM)
{
	char sql[SQL_BUF_MAX] = "\0";
	int getPsta = 0;

	MEMSET_STRING(sql,SQL_BUF_MAX)
	strcpy(sql, "select id,psta from progress where id = 2;");
	if (sql_get_ont_item(sql, GET_INTEGER, &getPsta, NULL) == -1)
	{
		// insert
		MEMSET_STRING(sql,SQL_BUF_MAX)
		snprintf(sql, SQL_BUF_MAX, "insert into progress(id,psta) values(%d,%d);", 2, _clearE2ROM);
    	return insert_date_sql(sql);
	}
	else
	{
		// update
		MEMSET_STRING(sql,SQL_BUF_MAX)
		snprintf(sql, SQL_BUF_MAX, "update progress set psta = %d where id = 2;", _clearE2ROM);
		return sql_update(sql);
	}
}


int sql_get_JN5169_clear_E2ROM_flag(void)
{
	char sql[SQL_BUF_MAX] = "\0";
	int getPsta = 0;

	MEMSET_STRING(sql,SQL_BUF_MAX)
	strcpy(sql, "select id,psta from progress where id = 2;");
	if (sql_get_ont_item(sql, GET_INTEGER, &getPsta, NULL) == -1)
	{
		return 0;
	}
	return getPsta;
}

int sql_check_allow_insert_mark_status(const char* checkMarkBuf, const char* insertMarkBuf)
{
	char sql[SQL_BUF_MAX] = "\0";
	int notUse;
	int ret = 0;
	
	MEMSET_STRING(sql,SQL_BUF_MAX)
	m_strncpy(sql, checkMarkBuf, SQL_BUF_MAX);
	if (sql_get_ont_item(sql, GET_INTEGER, &notUse, NULL) == -1)
	{
		MEMSET_STRING(sql,SQL_BUF_MAX)
		m_strncpy(sql, insertMarkBuf, SQL_BUF_MAX);
    	ret = insert_date_sql(sql);
	}

	return ret;
} 

emReturnStatus init_db_data(void)
{
	do 
	{
		if (sql_check_allow_insert_mark_status("select id,psta from progress where id = 1;"
			,"insert into progress(id,over,nver,psta,pros,gwver,mtt,jnt) values(1,0,0,1,0,101,86400,86400);") == -1) break;

		if (sql_check_allow_insert_mark_status("select id,tk from report where id = 1;"
			,"insert into report(id,gmacid,tk,powt,pows,devt,devs,ndevt,ndevs,sip,sport) values(1,'0','0',3600,1,300,1,10,0,'192.168.90.231',8082);") == -1) break;

		if (sql_check_allow_insert_mark_status("select id,tag,sta,pid from rooms where id = 1;"
			,"insert into rooms(id,tag,sta,pid) values(1,1,500,10);") == -1) break;

		/* init plug alarm defalus value is 90% */
		if (sql_check_allow_insert_mark_status("select id,tag,sta,pid from rooms where id = 2;"  
			,"insert into rooms(id,tag) values(2,90);") == -1) break;

		_DBG("init DB data successful.\n");
		return RE_SUCCESSFUL;
	}
	while (0);

	return RE_ERROR;
}

/*
*	return: 0 joined, -1 not join
*/
int sql_check_device_join_group_status(int groupNum, const char* devMacAddr)
{
	char sql[SQL_BUF_MAX] = "\0";
	char getDevAddGroupList[SIZE_1K] = "\0";
	int notUse = 0;
	char devMacBuf[SIZE_512B] = "\0";
	char* p_groupListNum = NULL;
	char delims[] = ",";
	char groupNumBuf[16] = "\0";

	MEMSET_STRING(sql, SQL_BUF_MAX)
	MEMSET_STRING(getDevAddGroupList, SIZE_1K)
	MEMSET_STRING(devMacBuf,SIZE_512B)

	m_strncpy(devMacBuf, devMacAddr, SIZE_512B);
	snprintf(sql, SQL_BUF_MAX, "select id,addgl from devices where mact = '%s';", devMacBuf);
	if (sql_get_ont_item(sql, GET_STRING, &notUse, getDevAddGroupList) == 0)
	{
		p_groupListNum = NULL;
		p_groupListNum = strtok(getDevAddGroupList, delims);
		while (p_groupListNum != NULL)
		{
			MEMSET_STRING(groupNumBuf,16)
			m_strncpy(groupNumBuf, p_groupListNum, 16);

			if (atoi(groupNumBuf) == groupNum)
			{
				_DBG("[MAC:%s] do not add group[%d] again.\n", devMacBuf, groupNum);
				return 0;
			}
			p_groupListNum = strtok(NULL, delims);
		}
	}
	
	return -1;
}

/*
*	return: 0 OK, -1 NOK
*/
int sql_get_schedule_time_list(int timeHour, int timeMin, emScheduleType* scheduleFlag)
{
	int ret = -1, ncol = 0;
    sqlite3* conn;
    char** array;
    char sql[SQL_BUF_MAX] = "\0";
	int i = 0;
	struct tm _t;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', SQL_BUF_MAX);
    strcpy(sql, "select id, tag, time, pid from timers;");
   // SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

	i = ncol;
	ret = -1;
    while (array[i] != NULL)
    {
    	//_DBG("GET DB TIME: %s\n", array[i+2]);
		sscanf(array[i+2], "%d-%d-%d %d:%d:%d", &_t.tm_year,&_t.tm_mon, &_t.tm_mday,&_t.tm_hour,&_t.tm_min, &_t.tm_sec);
		if (timeHour == _t.tm_hour && timeMin == _t.tm_min)
		{
			_DBG("Time lock, ready send\n");
			*scheduleFlag = atoi(array[i+1]);
			ret = 0;
			break;
		}
        
		i += ncol;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return ret;
}

/*
*	return: 0 OK, -1 error
*/
int sql_init_report_msg_struct(stReportTimeandSwitch* stReportandSwitch)
{
	int ret = -1, ncol = 0;
    sqlite3* conn;
    char** array;
    char sql[SQL_BUF_MAX] = "\0";
	int i = 0;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', SQL_BUF_MAX);
    strcpy(sql, "select powt, pows, devt, devs, ndevt, ndevs, sip, sport from report where id = 1;");
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

	i = ncol;
	ret = -1;
    if(array[i] != NULL)
    {
		stReportandSwitch->powerTime 			= REPLACE_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[i]))  ,3600);
		stReportandSwitch->powerSwitch 			= REPLACE_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[i+1])),1);
		stReportandSwitch->deviceChangeTime		= REPLACE_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[i+2])),300);
		stReportandSwitch->deviceChangeStatus 	= REPLACE_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[i+3])),1);
		stReportandSwitch->addDeviceTime 		= REPLACE_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[i+4])),10);
		stReportandSwitch->addDeviceSwitch 		= REPLACE_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[i+5])),0);
		ret = 0;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return ret;
}

int sql_init_plug_abnormal_parameter(uint32* timeV, uint32* configV, uint32* limitV)
{
	int ret = -1, ncol = 0;
    sqlite3* conn;
    char** array;
    char sql[SQL_BUF_MAX] = "\0";
	int i = 0;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', SQL_BUF_MAX);
    strcpy(sql, "select id, tag, sta, pid from rooms where id = 1;");
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

	i = ncol;
	ret = -1;
    if(array[i] != NULL)
    {
		*configV	= REPLACE_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[i+2])),1);
		*limitV	= REPLACE_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[i+3])),500);
		*timeV 	= REPLACE_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[i+1])),10);
		ret = 0;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return ret;
}

int sql_update_plug_ratedwatt(uint16 u16MsgNwkAddr, uint16 u16PlugRatedWatt)
{
	char sql[SIZE_512B] = "\0";
	int ret = -1;

	MEMSET_STRING(sql, SIZE_512B)
	/* define devices pid is pulg reted watt */
	snprintf(sql, SIZE_512B, "update devices set pid = %d where addr = %d;", u16PlugRatedWatt, u16MsgNwkAddr);
	ret = sql_update(sql);

	return ret;
}

/*
*	return: -1, get plug alarm error
*/
int sql_init_plug_alarm_value(void)
{
	char sql[SQL_BUF_MAX] = "\0";
	int plugAlarmValue = -1;

	MEMSET_STRING(sql, SQL_BUF_MAX)
	strcpy(sql, "select id, tag, sta, pid from rooms where id = 2;");
	sql_get_ont_item(sql, GET_INTEGER, &plugAlarmValue, NULL);

	return plugAlarmValue;
}

int sql_update_plug_alarm_value(uint16 plugAlarmValue)
{
	char sql[SIZE_256B] = "\0";
	int ret = -1;

	MEMSET_STRING(sql, SIZE_256B)
	/* define rooms id = 2, tag is pulg alarm value */
	snprintf(sql, SIZE_256B, "update rooms set tag = %d where id = 2;", plugAlarmValue);
	ret = sql_update(sql);

	return ret;
}

int sql_add_task_handler_set_plug_alarm_value(uint16 plugAlarmValue)
{
	char sql[SIZE_512B] = "\0";
	int getPsta = 0;

	MEMSET_STRING(sql,SIZE_512B)
	strcpy(sql, "select tid,gid from grouptask where tid = 'setPlugAlarmValueTid';");
	if (sql_get_ont_item(sql, GET_INTEGER, &getPsta, NULL) == -1)
	{
		// insert
		_DBG_INDEX();
		MEMSET_STRING(sql,SIZE_512B)
		snprintf(sql, SIZE_512B, "insert into grouptask(tid,gid,cfg,tsta) values('%s',%d,%d,%d);"
		, "setPlugAlarmValueTid", plugAlarmValue, T_CLT_SET_PLUG_ALARM_VALUE, T_HANDLER_NOT_START);
    	return insert_date_sql(sql);
	}
	else
	{
		// update
		_DBG_INDEX();
		MEMSET_STRING(sql,SIZE_512B)
		snprintf(sql, SIZE_512B, "update grouptask set gid = %d, tsta = %d where tid = 'setPlugAlarmValueTid';"
		, plugAlarmValue, T_HANDLER_NOT_START);
		return sql_update(sql);
	}

	_DBG("Add set plug task on DB done.\n");
	return 0;
}

int sql_get_all_plug_to_array(int* pa_sAddr, int* plugTotalLen)
{
	int ret = -1, ncol = 0;
    sqlite3* conn;
    char** array;
    char sql[SQL_BUF_MAX] = "\0";
	int i = 0;
	int index = 0;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', SQL_BUF_MAX);
    strcpy(sql, "select id, addr from devices where tag = 65;");
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

	i = ncol;
	ret = -1;
    while(array[i] != NULL)
    {
    	pa_sAddr[index++] = CHECKOUT_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[i+1])));
		i += ncol;
		ret = 0;
    }

	*plugTotalLen = index;	/* count plug */

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
	
    return ret;
}

int sql_get_device_tag_and_rated_watt(uint16 u16DeviceAddr, uint16* pu16DeviceTag, uint16* pu16DeviceRatedWatt)
{
	int ret = -1, ncol = 0;
    sqlite3* conn;
    char** array;
    char sql[SIZE_512B] = "\0";
	int i = 0;
	int index = 0;

    ADD_LOCK(lockDB)
    ret = sqlite3_open(ZGW_DB, &conn);
    IF_OPEN_DB_ERR(ret,conn)

    memset(sql, '\0', SIZE_512B);
    snprintf(sql, SIZE_512B, "select id, tag, pid from devices where addr = %d;", u16DeviceAddr);
    SQL_DBG("sql: %s\n", sql);
    ret = executeWithQuery(conn, &array, &ncol, sql);
    IF_SQL_ERR(ret,conn)

	i = ncol;
	ret = -1;
    if(array[i] != NULL)
    {
    	*pu16DeviceTag = CHECKOUT_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[i+1])));
		*pu16DeviceRatedWatt = CHECKOUT_GREATER_THAN_ZERO(atoi(CHECKOUT_REPORT_DATE(array[i+2])));
		i += ncol;
		ret = 0;
    }

    sqlite3_free_table(array);
    sqlite3_close(conn);
    FREE_LOCK(lockDB)
    return ret;
}

int sql_set_plug_alarm_flag(uint16 deviceSaddr)
{
	char sql[SIZE_256B] = "\0";
	int ret = -1;

	MEMSET_STRING(sql, SIZE_256B)
	snprintf(sql, SIZE_256B, "update devices set uid = 1 where addr = %d;", deviceSaddr);
	ret = sql_update(sql);

	return ret;
}