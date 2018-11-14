/****************************************************************************
test demo:
(1)chunked receive data
http_download( "http://www.httpwatch.com/httpgallery/chunked/chunkedimage.aspx", "test.aspx")
(2)redirecter test
http_download( "192.168.10.1/main.html", "test.txt")
(3)error parameter input
http_download( "32131233", "test.txt")
(4)root url test
http_download( "www.baidu.com/", "test.txt")
(5)port test
http_download( "192.168.0.200:8000/FS_AC6V1.0BR_V15.03.4.12_multi_TD01.bin", "test.txt")
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>

#include <time.h>
#include <ifaddrs.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>
#include <zigbee.h>

#define HOST_NAME_LEN   256
#define URI_MAX_LEN     2048
#define RECV_BUF        8192
#define RCV_SND_TIMEOUT (10*1000)   //send or receive timeout

typedef struct {
    int sock;                       //socket
    FILE *in;                       
    char host_name[HOST_NAME_LEN];  //host name
    int port;                       //host port
    char uri[URI_MAX_LEN];          //resources path
    char buffer[RECV_BUF];          //read/write buffer
    int status_code;                //http status
    int chunked_flag;               //chunked transfer flag
    int len;                        //Content-length length
    char location[URI_MAX_LEN];     //redirect path
    char *save_path;                //save conment path pointer
    FILE *save_file;                //save comment file pointer
    int recv_data_len;              //receive date length
    time_t start_recv_time;         //start recevice date time
    time_t end_recv_time;           //end recevice date time
} http_t;

#define MSG_DEBUG   0x01
#define MSG_INFO    0x02
#define MSG_ERROR   0x04

static int print_level = /*MSG_DEBUG |*/ MSG_INFO | MSG_ERROR;

#define lprintf(level, format, argv...) do{     \
    if(level & print_level)     \
        printf("[%s][%s(%d)]:"format, #level, __FUNCTION__, __LINE__, ##argv);  \
}while(0)

#define MIN(x, y) ((x) > (y) ? (y) : (x))

#define HTTP_OK         200
#define HTTP_REDIRECT   302
#define HTTP_NOT_FOUND  404

char *strncasestr(char *str, char *sub)
{
    if(!str || !sub)
        return NULL;

    int len = strlen(sub);
    if (len == 0)
    {
        return NULL;
    }

    while (*str)
    {
        if (strncasecmp(str, sub, len) == 0)
        {
            return str;
        }
        ++str;
    }
    return NULL;
}

/* analysis URL return: OK 0, error: -1 */
/* http://127.0.0.1:8080/testfile */
int parser_URL(char *url, http_t *info)
{
    char *tmp = url, *start = NULL, *end = NULL;
    int len = 0;

    /* ignore http:// */
    if(strncasestr(tmp, "http://"))
    {   
        tmp += strlen("http://");
    }
    start = tmp;
    if(!(tmp = strchr(start, '/')))
    {
        lprintf(MSG_ERROR, "url invaild\n");
        return -1;      
    }
    end = tmp;

    /* analysis host and port */
    info->port = 80;   //init value: 80

    len = MIN(end - start, HOST_NAME_LEN - 1);
    strncpy(info->host_name, start, len);
    info->host_name[len] = '\0';

    if((tmp = strchr(start, ':')) && tmp < end)
    {
        info->port = atoi(tmp + 1);
        if(info->port <= 0 || info->port >= 65535)
        {
            lprintf(MSG_ERROR, "url port invaild\n");
            return -1;
        }
        /* cover init value */
        len = MIN(tmp - start, HOST_NAME_LEN - 1);
        strncpy(info->host_name, start, len);
        info->host_name[len] = '\0';
    }

    /* copy url */
    start = end;
    strncpy(info->uri, start, URI_MAX_LEN - 1);

    lprintf(MSG_INFO, "parse url ok\nhost:%s, port:%d, uri:%s\n", 
        info->host_name, info->port, info->uri);
    return 0;
}

/* dns analysis,return the first value. 
*   return: address OK, -1 error
*/
unsigned long dns(char* host_name)
{

    struct hostent* host;
    struct in_addr addr;
    char **pp;

    host = gethostbyname(host_name);
    if (host == NULL)
    {
        lprintf(MSG_ERROR, "gethostbyname %s failed\n", host_name);
        return -1;
    }

    pp = host->h_addr_list;

    if (*pp!=NULL)
    {
        addr.s_addr = *((unsigned int *)*pp);
        lprintf(MSG_INFO, "%s address is %s\n", host_name, inet_ntoa(addr));
        pp++;
        return addr.s_addr;
    }

    return -1;
}

/* set send data timeout */
int set_socket_option(int sock)
{
    struct timeval timeout;

    timeout.tv_sec = RCV_SND_TIMEOUT/1000;
    timeout.tv_usec = RCV_SND_TIMEOUT%1000*1000;
    lprintf(MSG_DEBUG, "%ds %dus\n", (int)timeout.tv_sec, (int)timeout.tv_usec);

    // set send data timeout
    if(-1 == setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, 
            sizeof(struct timeval)))
    {
        lprintf(MSG_ERROR, "setsockopt error: %m\n");
        return -1;
    }

    // set receive data timeout
    if(-1 == setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, 
            sizeof(struct timeval)))
    {
        lprintf(MSG_ERROR, "setsockopt error: %m\n");
        return -1;
    }

    return 0;
}

/* connect to server */
int connect_server(http_t *info)
{
    int sockfd;
    struct sockaddr_in server;
    unsigned long addr = 0;
    unsigned short port = info->port;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == sockfd)
    {
        lprintf(MSG_ERROR, "socket create failed\n");
        goto failed;
    }

    if(-1 == set_socket_option(sockfd))
    {
        goto failed;
    }

    if ((addr = dns(info->host_name)) == -1)
    {
        lprintf(MSG_ERROR, "Get Dns Failed\n");
        goto failed;
    }
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET; 
    server.sin_port = htons(port); 
    server.sin_addr.s_addr = addr;

    if (-1 == connect(sockfd, (struct sockaddr *)&server, sizeof(struct sockaddr)))
    {
        lprintf(MSG_ERROR, "connect failed: %m\n");
        goto failed;
    }

    info->sock = sockfd;
    return 0;

failed:
    if(sockfd != -1)
        close(sockfd);
    return -1;
}

/* send http request */
int send_request(http_t *info)
{
    int len;

    memset(info->buffer, 0x0, RECV_BUF);
    snprintf(info->buffer, RECV_BUF - 1, "GET %s HTTP/1.1\r\n"
        "Accept: */*\r\n"
        "User-Agent: Mozilla/5.0 (compatible; MSIE 5.01; Windows NT 5.0)\r\n"
        "Host: %s\r\n"
        "Connection: Close\r\n\r\n", info->uri, info->host_name);

    lprintf(MSG_DEBUG, "request:\n%s\n", info->buffer);
    return send(info->sock, info->buffer, strlen(info->buffer), 0);
}

/* analysis http head */
int parse_http_header(http_t *info)
{
    char *p = NULL;

    // analysis row 1
    fgets(info->buffer, RECV_BUF, info->in);
    p = strchr(info->buffer, ' ');
    //check the row 1 whether legal
    if(!p || !strcasestr(info->buffer, "HTTP"))
    {
        lprintf(MSG_ERROR, "bad http head\n");
        return -1;
    }
    info->status_code = atoi(p + 1);   
    lprintf(MSG_DEBUG, "http status code: %d\n", info->status_code);

    // loop analysis http head
    while(fgets(info->buffer, RECV_BUF, info->in))
    {
        // check the head whether end
        if(!strcmp(info->buffer, "\r\n"))
        {
            return 0;   /* analysis ok */
        }
        lprintf(MSG_DEBUG, "%s", info->buffer);
        // analysis msg length, Content-length: 554
        if(p = strncasestr(info->buffer, "Content-length"))
        {
            p = strchr(p, ':');
            p += 2;     // jump ":" and laster space
            info->len = atoi(p);
            lprintf(MSG_INFO, "Content-length: %d\n", info->len);
        }
        else if(p = strncasestr(info->buffer, "Transfer-Encoding"))
        {
            if(strncasestr(info->buffer, "chunked"))
            {
                info->chunked_flag = 1;
            }
            else
            {
                /* not support other transfor form */
                lprintf(MSG_ERROR, "Not support %s", info->buffer);
                return -1;
            }
            lprintf(MSG_INFO, "%s", info->buffer);
        }
        else if(p = strncasestr(info->buffer, "Location"))
        {
            p = strchr(p, ':');
            p += 2;     // jump ":" and laster space
            strncpy(info->location, p, URI_MAX_LEN - 1);
            lprintf(MSG_INFO, "Location: %s\n", info->location);
        }
    }
    lprintf(MSG_ERROR, "bad http head\n");
    return -1;  /* analysis error */
}

/* save server send data */
int save_data(http_t *info, const char *buf, int len)
{
    int total_len = len;
    int write_len = 0;

    // if file not exist then open
    if(!info->save_file)
    {
        info->save_file = fopen(info->save_path, "w");
        if(!info->save_file)
        {
            lprintf(MSG_ERROR, "fopen %s error: %m\n", info->save_path);
            return -1;
        }
    }

    while(total_len)
    {
        write_len = fwrite(buf, sizeof(char), len, info->save_file);
        if(write_len < len && errno != EINTR)
        {
            lprintf(MSG_ERROR, "fwrite error: %m\n");
            return -1;
        }
        total_len -= write_len;
    }
	return 0;
}

/* read data */
int read_data(http_t *info, int len)
{
    int total_len = len;
    int read_len = 0;
    int rtn_len = 0;

    while(total_len)
    {
        read_len = MIN(total_len, RECV_BUF);
        
        rtn_len = fread(info->buffer, sizeof(char), read_len, info->in);
        if(rtn_len < read_len)
        {
            if(ferror(info->in))
            {
                if(errno == EINTR) /* single is break */
                {
                    ;   /* do not anything */
                }
                else if(errno == EAGAIN || errno == EWOULDBLOCK) /* timeout */
                {
                    lprintf(MSG_ERROR, "socket recvice timeout: %dms\n", RCV_SND_TIMEOUT);
                    total_len -= rtn_len;
                    lprintf(MSG_DEBUG, "read len: %d\n", rtn_len);
                    break;
                }
                else    /* other error */
                {
                    lprintf(MSG_ERROR, "fread error: %m\n");
                    break;
                }
            }
            else    /* read to the file end */
            {
                lprintf(MSG_ERROR, "socket closed by peer\n");
                total_len -= rtn_len;
                lprintf(MSG_DEBUG, "read len: %d\n", rtn_len);
                break;
            }
        }

        total_len -= rtn_len;
        lprintf(MSG_DEBUG, "read len: %d\n", rtn_len);
        if(-1 == save_data(info, info->buffer, rtn_len))
        {
            return -1;
        }
        info->recv_data_len += rtn_len;
    }
    if(total_len != 0)
    {
        lprintf(MSG_ERROR, "we need to read %d bytes, but read %d bytes now\n", 
            len, len - total_len);
        return -1;
    }
}

/* receive server send chunked data */
int recv_chunked_response(http_t *info)
{
    long part_len;

    do{
        fgets(info->buffer, RECV_BUF, info->in);
        part_len = strtol(info->buffer, NULL, 16);
        lprintf(MSG_DEBUG, "part len: %ld\n", part_len);
        if(-1 == read_data(info, part_len))
            return -1;

        // read last \r\n two character
        if(2 != fread(info->buffer, sizeof(char), 2, info->in))
        {
            lprintf(MSG_ERROR, "fread \\r\\n error : %m\n");
            return -1;
        }
    }while(part_len);
    return 0;
}

/* Calculate the average download speed, byte/s */
float calc_download_speed(http_t *info)
{
    int diff_time = 0; 
    float speed = 0.0;

    diff_time = info->end_recv_time - info->start_recv_time;
    
    if(0 == diff_time)
        diff_time = 1;
    speed = (float)info->recv_data_len / diff_time;

    return  speed;
}

/* receive server responser data */
int recv_response(http_t *info)
{
    int len = 0, total_len = info->len;

    if(info->chunked_flag)
        return recv_chunked_response(info);

    if(-1 == read_data(info, total_len))
        return -1;

    return 0;
}

/* clean */
void clean_up(http_t *info)
{
    if(info->in)
        fclose(info->in);
    if(-1 != info->sock)
        close(info->sock);
    if(info->save_file)
        fclose(info->save_file);
    if(info)
        free(info);
}

/* download function */
int http_download(char *url, char *save_path, int* fileLength)
{
    http_t *info = NULL;
    char tmp[URI_MAX_LEN] = {0};

    if(!url || !save_path)
        return -1;

    //init struct
    info = malloc(sizeof(http_t));
    if(!info)
    {
        lprintf(MSG_ERROR, "malloc failed\n");
        return -1;
    }
    memset(info, 0x0, sizeof(http_t));
    info->sock = -1;
    info->save_path = save_path;

    // analysis url
    if(-1 == parser_URL(url, info))
        goto failed;

    // connent to server
    if(-1 == connect_server(info))
        goto failed;

    // send http head
    if(-1 == send_request(info))
        goto failed;

    // receive response message head
    info->in = fdopen(info->sock, "r");
    if(!info->in)
    {
        lprintf(MSG_ERROR, "fdopen error\n");
        goto failed;
    }

    // analysis head
    if(-1 == parse_http_header(info))
        goto failed;

    switch(info->status_code)
    {
        case HTTP_OK:
            // receive data
            lprintf(MSG_DEBUG, "recv data now\n");
            info->start_recv_time = time(0);
            if(-1 == recv_response(info))
                goto failed;

            info->end_recv_time = time(0);
			*fileLength = info->recv_data_len;
            lprintf(MSG_INFO, "recv %d bytes\n", info->recv_data_len);
            lprintf(MSG_INFO, "Average download speed: %.2fKB/s\n", 
                    calc_download_speed(info)/1000);
            break;
        case HTTP_REDIRECT:
            // resume this function
            lprintf(MSG_INFO, "redirect: %s\n", info->location);
            strncpy(tmp, info->location, URI_MAX_LEN - 1);
            clean_up(info);
            return http_download(tmp, save_path, fileLength);

        case HTTP_NOT_FOUND:
            // exist
            lprintf(MSG_ERROR, "Page not found\n");
            goto failed;
            break;

        default:
            lprintf(MSG_INFO, "Not supported http code %d\n", info->status_code);
            goto failed;
    }

    clean_up(info);
    return 0;
failed:
    clean_up(info);
    return -1;
}