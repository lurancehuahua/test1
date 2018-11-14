#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <netdb.h>
#include <ifaddrs.h>
#include <net/if_arp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#include <pthread.h>
#include <zigbee.h>

#include "zigbee_sqlite3.h"


#include <signal.h>
#include <zigbee.h>

extern int log_zigbee_status(int zigbeeStatus, int zigbeeWatchdog);




#define SOCKET_DBG(...)   printf(__VA_ARGS__)
#define SOCKET_INFO(...)

#define IP_SIZE     16
#define MAC_SIZE    18

char stringTkBuf[256] = "\0";

int get_ip_by_domain(const char *domain, char *ip);
int get_local_ip(const char *eth_inf, char *ip);
int get_local_mac(const char *eth_inf, char *mac);
int get_peermac_byfd(int sockfd, char *buf);

void get_sendmsg(char *buf);

void udp_process(void);
void tcp_process(void);
int initSocket(void);

emReturnStatus socket_init_report_tk(void)
{
	if (sql_init_report_tk_buffer(stringTkBuf) == 0)
	{
		_DBG("INIT report tk: %s\n", stringTkBuf);
		return RE_SUCCESSFUL;
	}
	else
	{
		_DBG("[Error]INIT report tk\n");
		return RE_ERROR;
	}
}

void socket_update_report_tk(const char* updateTkBuf)
{
	if (updateTkBuf != NULL)
	{
		memset(stringTkBuf, '\0', 256);
		m_strncpy(stringTkBuf, updateTkBuf, 256);
	}
}

// 根据域名获取ip
int get_ip_by_domain(const char *domain, char *ip)
{
    char **pptr;
    struct hostent *hptr;

    hptr = gethostbyname(domain);
    if(NULL == hptr)
    {
        printf("gethostbyname error for host:%s/n", domain);
        return -1;
    }

    for(pptr = hptr->h_addr_list ; *pptr != NULL; pptr++)
    {
        if (NULL != inet_ntop(hptr->h_addrtype, *pptr, ip, IP_SIZE) )
        {
            return 0; // 只获取第一个 ip
        }
    }
    return -1;
}


// 获取本机ip
int get_local_ip(const char *eth_inf, char *ip)
{
    int sd;
    struct sockaddr_in sin;
    struct ifreq ifr;

    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == sd)
    {
        printf("socket error: %s\n", strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, eth_inf, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    // if error: No such device
    if (ioctl(sd, SIOCGIFADDR, &ifr) < 0)
    {
        printf("ioctl error: %s\n", strerror(errno));

        close(sd);
        return -1;
    }

    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
    snprintf(ip, IP_SIZE, "%s", inet_ntoa(sin.sin_addr));

    close(sd);
    return 0;
}


int get_local_mac(const char *eth_inf, char *mac)
{
    struct ifreq ifr;
    int sd;

    bzero(&ifr, sizeof(struct ifreq));
    if( (sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("get %s mac address socket creat error\n", eth_inf);
        return -1;
    }

    strncpy(ifr.ifr_name, eth_inf, sizeof(ifr.ifr_name) - 1);

    if(ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
    {
        printf("get %s mac address error\n", eth_inf);
        close(sd);
        return -1;
    }

    snprintf(mac, MAC_SIZE, "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)ifr.ifr_hwaddr.sa_data[0],
             (unsigned char)ifr.ifr_hwaddr.sa_data[1],
             (unsigned char)ifr.ifr_hwaddr.sa_data[2],
             (unsigned char)ifr.ifr_hwaddr.sa_data[3],
             (unsigned char)ifr.ifr_hwaddr.sa_data[4],
             (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    close(sd);

    return 0;
}


int get_peermac_byfd(int sockfd, char *buf)
{
    int ret =0;
    struct arpreq arpreq;
    struct sockaddr_in dstadd_in;
    socklen_t  len = sizeof( struct sockaddr_in );

    memset( &arpreq, 0, sizeof( struct arpreq ));
    memset( &dstadd_in, 0, sizeof( struct sockaddr_in ));

    if( getpeername( sockfd, (struct sockaddr*)&dstadd_in, &len ) < 0 )
        SOCKET_DBG("getpeername()");
    else
    {
        memcpy( &arpreq.arp_pa, &dstadd_in, sizeof( struct sockaddr_in ));
        strcpy(arpreq.arp_dev, "br-lan");
        arpreq.arp_pa.sa_family = AF_INET;
        arpreq.arp_ha.sa_family = AF_UNSPEC;
        if( ioctl( sockfd, SIOCGARP, &arpreq ) < 0 )
            SOCKET_DBG("ioctl SIOCGARP");
        else
        {
            unsigned char* ptr = (unsigned char *)arpreq.arp_ha.sa_data;
            ret = sprintf(buf, "%02x%02x%02x%02x%02x%02x", *ptr, *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5));

            SOCKET_DBG("PEER_MAC = %s\n", buf);
        }
    }

    return ret;
}


void get_sendmsg(char *buf)
{
    char sndMsg[256];

    char ip[IP_SIZE];
    char mac[MAC_SIZE];
    //const char *test_domain = "www.baidu.com";
    const char *test_eth = "br-lan";

    //get_ip_by_domain(test_domain, ip);
    //printf("%s ip: %s\n", test_domain, ip);

    get_local_mac(test_eth, mac);
    printf("local %s mac: %s\n", test_eth, mac);

    get_local_ip(test_eth, ip);
    printf("local %s ip: %s\n", test_eth, ip);

    memset(sndMsg, '\0', 256);
    //strncat(sndMsg, "Greeble Zigbee Gateway ! ", 32);
    strncat(sndMsg, "Greeble", 8);
    strncat(sndMsg, " IP: ", 8);
    strncat(sndMsg, ip, IP_SIZE);
    strncat(sndMsg, " MAC: ", 8);
    strncat(sndMsg, mac, MAC_SIZE);
    strncat(sndMsg, "\n", 8);

    snprintf(buf, BUFSIZ, sndMsg);

    return;
}

#if 1
#define BUF_LEN 1028
#define SERVER_PORT 8082

const static char http_error_hdr[] = "HTTP/1.1 404 Not Found\r\nContent-type: text/html\r\n\r\n";
const static char http_html_hdr[] = "HTTP/1.1 200 OK\r\nContent-type: text/html\r\n\r\n";
const static char http_index_html[] =
    "<html><head><title>Congrats!</title></head>"
    "<body><h1>Welcome to our HTTP server demo!</h1>"
    "<p>This is a just small test page.</body></html>";

int http_send_file(char *filename, int sockfd)
{
    if(!strcmp(filename, "/"))
    {
        write(sockfd, http_html_hdr, strlen(http_html_hdr));
        write(sockfd, http_index_html, strlen(http_index_html));
    }
    else
    {
        printf("%s:file not find!\n",filename);
        write(sockfd, http_error_hdr, strlen(http_error_hdr));
    }
    return 0;
}

void serve(int sockfd)
{
    char buf[BUF_LEN];
    read(sockfd, buf, BUF_LEN);
    if(!strncmp(buf, "GET", 3))
    {
        char *file = buf + 4;
        char *space = strchr(file, ' ');
        *space = '\0';
        http_send_file(file, sockfd);
    }
    else
    {
        printf("unsupported request!\n");
        return;
    }
}

void zgw_server_socket(void)
{
    int sockfd,newfd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
    {
        perror("socket creation failed!\n");
        return;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    if(bind(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)))
    {
        perror("socket binding failed!\n");
        return;
    }
    listen(sockfd, 128);
    printf("Create server ok.\n");
    for(;;)
    {
        newfd = accept(sockfd, NULL, NULL);

        printf("accept a client: %d.\n", newfd);

        serve(newfd);
        close(newfd);
    }
}

#endif

int socket_read_timeout(int fd, char *buf,
		   unsigned int buf_len, unsigned int *read_len,
		   unsigned int timeout)
{
	int ret;
	fd_set set;
	int r;
	struct timeval tv;


	FD_ZERO(&set);
	FD_SET(fd, &set);
	tv.tv_sec = (timeout * 1000) / 1000000;
	tv.tv_usec = (timeout * 1000) % 1000000;
	*read_len = 0;

	ret = select(fd+1, &set, NULL, NULL, &tv);
	switch (ret) {
	case 0:
		_DBG("%s\n", "Socket_ERR_READ");
		return 0;
	case 1:
		r = read(fd, buf, buf_len);
		if (r == -1) {
			_DBG("errno: %d strerror: %s %s\n",
			    errno, strerror(errno), "Socket_ERR_READ");
			return 1;
		}

		*read_len = r;
		break;
	default:
		_DBG("%s\n", "RS232_ERR_SELECT");
		return -1;
	}

	return -1;
}


void get_send_cloud_msg_head(char* buf)
{
    const static char s_HttpMsgHead[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    //const static char s_HttpMsgHead[] = "HTTP/1.1 200 OK\r\nContent-Type: application/json;charset=utf-8\r\n\r\n";
    const static char s_Http_test_content[] =
        "<html><head><title>Congrats!</title></head>"
        "<body><h1>Welcome to our HTTP server demo!</h1>"
        "<p>This is a just small test page.</body></html>";
    //const char *test_eth = "br-lan";
    //char sndMsg[256];
    //char ip[IP_SIZE];
    //char mac[MAC_SIZE];

    strcpy(buf, s_HttpMsgHead);
    strcat(buf, s_Http_test_content);

#if 0
    get_local_mac(test_eth, mac);
    //printf("local %s mac: %s\n", test_eth, mac);

    get_local_ip(test_eth, ip);
    //printf("local %s ip: %s\n", test_eth, ip);

    memset(sndMsg, '\0', 256);

    strncat(sndMsg, "Greeble", 8);
    strncat(sndMsg, " IP: ", 8);
    strncat(sndMsg, ip, IP_SIZE);
    strncat(sndMsg, " MAC: ", 8);
    strncat(sndMsg, mac, MAC_SIZE);
    strncat(sndMsg, "\n", 8);
#endif
    //strcpy(sndMsg, "{\"GMAC\":\"123456789\",\"STA\":3}");

    //strcat(buf, sndMsg);
}


void udp_process(void)
{
    int fd;
    char buf[BUFSIZ];
    struct sockaddr_in addr = {0};

    /* create what looks like an ordinary UDP socket */
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
		_DBG("[!!! exit]udp socket error.\n");
        exit(0);
    }

    /* set up destination address */
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    //addr.sin_addr.s_addr = inet_addr("239.100.100.203");
    addr.sin_addr.s_addr = inet_addr("224.0.0.1");
    addr.sin_port = htons(1324);

    memset(buf, '\0', BUFSIZ);
    get_sendmsg(buf);

    /* now just sendto() our destination! */
    while (1)
    {
        puts(buf);

        if (sendto(fd, buf, strlen(buf), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            perror("sendto");
            //exit(1);
        }
        sleep(20);
    }
}


void tcp_process(void)
{
#define SHORT_MSG_LEN  32
    extern int isButtonPressed(void);

    int server_sockfd;
    int client_sockfd;
    struct sockaddr_in my_addr;
    struct sockaddr_in remote_addr;
    int sin_size;
    char buf[BUFSIZ];

    memset(&my_addr,0,sizeof(my_addr));
    my_addr.sin_family=AF_INET;
    my_addr.sin_addr.s_addr=INADDR_ANY;
    my_addr.sin_port=htons(8000);

    if((server_sockfd=socket(PF_INET,SOCK_STREAM,0))<0)
    {
        perror("socket");
        return;
    }

    if (bind(server_sockfd,(struct sockaddr *)&my_addr,sizeof(struct sockaddr))<0)
    {
        perror("bind");
        return;
    }

    listen(server_sockfd,5);

    sin_size=sizeof(struct sockaddr_in);

    while (1)
    {
        sleep(2);

        if((client_sockfd=accept(server_sockfd,(struct sockaddr *)&remote_addr, &sin_size))<0)
        {
            perror("accept");
            continue;
        }

        printf("accept client %s\n",inet_ntoa(remote_addr.sin_addr));

        memset(buf, '\0', BUFSIZ);
        get_sendmsg(buf);
        send(client_sockfd,buf,strlen(buf),0);
        //send(client_sockfd,"Welcome to Greeble!\n",SHORT_MSG_LEN,0);

#if 0 //bind process
        do
        {
            int bindStatus;
            char macbuf[MAC_SIZE];

            bindStatus = 0;
            memset(macbuf, '\0', MAC_SIZE);

            //while(len = (recv(client_sockfd,buf,BUFSIZ,0))>0)
            get_peermac_byfd(client_sockfd, macbuf);

            if (sql_query_mac(macbuf) == 1)
            {
                bindStatus = 0;
                send(client_sockfd,"0(Not Bind yet) !\n",SHORT_MSG_LEN,0);
            }
            else
            {
                bindStatus = 1;
                send(client_sockfd,"1(Bind already) !\n",SHORT_MSG_LEN,0);
            }

            if (bindStatus == 0)
            {
                if (isButtonPressed() == 1)
                {
                    sql_insert_mac(macbuf);
                }
            }
        }
        while(0);
#endif
        close(client_sockfd);
    }

    close(client_sockfd);
    close(server_sockfd);

    return;
}

/*
*	solve the port exiset using question by SO_REUSEADDR.
*/
void reuseAddr(int socketFd)
{
    int on = 1;
    int ret = setsockopt(socketFd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on));
    if(ret == -1)
    {
        fprintf(stderr, "Error : fail to setsockopt\n");
        return;
    }
}

void http_process(void)
{
	#define SHORT_MSG_LEN  32
    extern int isButtonPressed(void);
	extern int gw_server_handler_enter(char* receMsgBuf, int clientSocketId);

    int server_sockfd;
    int client_sockfd;
    struct sockaddr_in my_addr;
    struct sockaddr_in remote_addr;
    int sin_size;
    char* sendMsgBuf = NULL;
    int ret = 0;
	int reuse = 1;
	static int tryBuildHttpServerCount = 0;
	uint32 receiveDataSize = 0;

    APPLY_MEMORY_AND_CHECK(sendMsgBuf,RECEIVE_CLIENT_REQUEST_BUFFER_SIZE)

    memset(&my_addr,0,sizeof(my_addr));
    my_addr.sin_family=AF_INET;
    my_addr.sin_addr.s_addr=INADDR_ANY;
    my_addr.sin_port=htons(8080); //User Should update this port, need to apply API

    server_sockfd = socket(PF_INET,SOCK_STREAM,0);
	if (setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
		_DBG("[!!! exit]http server setsocket error.\n");
		exit(0);
        return ;
    }

    //euseAddr(server_sockfd);
    if (bind(server_sockfd,(struct sockaddr *)&my_addr,sizeof(struct sockaddr))<0)
    {
		_DBG("[!!! exit]http server bind error.\n");
		log_zigbee_status(0,1);        // if build gateway server error, exit thread, and then restart.
		exit(0);
        return;
    }

    listen(server_sockfd,5);

    sin_size=sizeof(struct sockaddr_in);
    _DBG("************** Create ZGW server successful.  Accept the client to connet. **********************\n");
    while (1)
    {
        if((client_sockfd = accept(server_sockfd,(struct sockaddr *)&remote_addr, &sin_size)) < 0)
        {
            perror("accept");
            continue;
        }

        memset(sendMsgBuf, '\0', RECEIVE_CLIENT_REQUEST_BUFFER_SIZE);
		
#define GW_SERVER_READ_TIMEOUT
#ifdef GW_SERVER_READ_TIMEOUT
		receiveDataSize = 0;
		ret = 0;
		while (1)
		{
			socket_read_timeout(client_sockfd, sendMsgBuf + ret, SIZE_1K, &receiveDataSize, 100);
			_DBG("Receive data size: %d\n", receiveDataSize);
			
			if (receiveDataSize <= 0 || (ret + receiveDataSize) >= RECEIVE_CLIENT_REQUEST_BUFFER_SIZE) break;
			ret += receiveDataSize;
			
		}

		_DBG("echo client request data:\n");
		int i = 0;
		for (i = 0; i < ret; i++)
		{
			printf("%c", sendMsgBuf[i]);
		}
		printf("\n");
#else
		ret = read(client_sockfd, sendMsgBuf, RECEIVE_CLIENT_REQUEST_BUFFER_SIZE);
#endif
        if (ret <= 0)
        {
            _DBG("read server request error.\n");
        }
        else
        {
            _DBG("accept client %s, dataLength:%d\n",inet_ntoa(remote_addr.sin_addr), ret);
			
            // Analysis sendMsgBuf to handler task
            gw_server_handler_enter(sendMsgBuf, client_sockfd);
        }

        close(client_sockfd);
    }

    close(client_sockfd);
    close(server_sockfd);
    FREE_APPLY_MEMORY(sendMsgBuf)

    return;
}


int initSocket(void)
{
    int ret;

    SOCKET_DBG("Enter: %s, %d\n", __FUNCTION__, __LINE__);

//#define USE_UDP
#ifdef USE_UDP
    pthread_t pThreadUdpId;
    ret = pthread_create(&pThreadUdpId, NULL, (void*)udp_process, NULL);
    if(ret != 0)
    {
        SOCKET_DBG("create udp_process thread error\n");
        return 1;
    }
#endif

// #define USE_TCP
#ifdef USE_TCP
    pthread_t pThreadTcpId;
    ret = pthread_create(&pThreadTcpId, NULL, (void*)tcp_process, NULL);
    if(ret != 0)
    {
        SOCKET_DBG("create tcp_process thread error\n");
        return 1;
    }
#endif

#define CLOUD_TCP
#ifdef CLOUD_TCP
    pthread_t pThreadCloudId;
    ret = pthread_create(&pThreadCloudId, NULL, (void*)http_process, NULL);
    if(ret != 0)
    {
        SOCKET_DBG("create http_process thread error\n");
		exit(0);
        return 1;
    }
#endif

    SOCKET_DBG("Leave: %s, %d\n", __FUNCTION__, __LINE__);

    return 0;
}

int report_msg2_server(char* sendMsgBuf, char* serverIp, uint16 serverPort, char* buf)
{
    //#define IPSTR "192.168.90.231"
    //#define PORT 8082
    //#define BUFSIZE 1024

    int sockfd, ret, i, h;
    struct sockaddr_in servaddr;
    //char str2[4096];
    char str1[4096], sendMsgLength[128];
    socklen_t len;
    fd_set   t_set1;
    struct timeval  tv;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    {
        printf("create socket error!\n");
        return -1;
        //exit(0);
    };

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
#ifdef PORT
    servaddr.sin_port = htons(PORT);
#else
    servaddr.sin_port = htons(serverPort);
#endif

#ifdef IPSTR
    if (inet_pton(AF_INET, IPSTR, &servaddr.sin_addr) <= 0 )
    {
        printf("inet_pton error!\n");
        return -1;
        //exit(0);
    };
#else
    if (inet_pton(AF_INET, serverIp, &servaddr.sin_addr) <= 0 )
    {
        printf("inet_pton error!\n");
        return -1;
        //exit(0);
    };
#endif

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        printf("[Report Baddly]: connect to server error!\n");
        return -1;
        //exit(0);
    }
    printf("connect to server OK.\n");

    // send data
    //memset(str2, '\0', 4096);
    ////strcat(str2, "{\"GMAC\":\"123456789\",\"LWEU\":[{\"MAC\":\"141235238832099\",\"WT\":150,\"EL\":5,\"UT\":120,\"LQI\":222}],\"md5\":\"12345678\"}");
    //strcat(str2, sendMsgBuf);

    memset(sendMsgLength, '\0', 128);
    len = strlen(sendMsgBuf);
    sprintf(sendMsgLength, "%d", len);

    memset(str1, 0, 4096);
  //strcat(str1, "POST /gwsa/gwdata.html?tk=");
	//strcat(str1, stringTkBuf);
	//strcat(str1, " HTTP/1.1\n");
	
	//strcat(str1, "POST /gwsa/gwdata.html HTTP/1.1\n");
    //strcat(str1, "Host: www.webxml.com.cn\n");


	strcat(str1, "POST /gwsa/gwdata.html HTTP/1.0\n");
  //  strcat(str1, "Host: www.webxml.com.cn\n");

	
    //strcat(str1, "Content-Type: application/x-www-form-urlencoded\n");
    strcat(str1, "Content-Type: application/json;charset=utf-8\n");
    strcat(str1, "Content-Length: ");
    strcat(str1, sendMsgLength);
    strcat(str1, "\n\n");

    strcat(str1, sendMsgBuf);
    strcat(str1, "\r\n\r\n");
    printf("%s\n",str1);

    ret = write(sockfd,str1,strlen(str1));
    if (ret < 0)
    {
        printf("send error: %d，error message:'%s'\n",errno, strerror(errno));
        return -1;
        //exit(0);
    }
    else
    {
        printf("send msg OK, total send %d byte.\n\n", ret);
    }

    FD_ZERO(&t_set1);
    FD_SET(sockfd, &t_set1);


    do
    {
        sleep(2);
        tv.tv_sec= 0;
        tv.tv_usec= 0;
        h= 0;
        h= select(sockfd +1, &t_set1, NULL, NULL, &tv);

        if (h < 0)
        {
            close(sockfd);
            printf("Get select error, socket be broken.\n");
            return -1;
        };

        if (h > 0)
        {
            memset(buf, '\0', REPORT_BUFF_SIZE);
            i= read(sockfd, buf, REPORT_BUFF_SIZE);
            if (i==0)
            {
                close(sockfd);
                printf("Read socked but the server be close.\n");
                return -1;
            }
        }
    }
    while(0);

    close(sockfd);
    return 0;
}


