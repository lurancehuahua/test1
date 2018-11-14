#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#define SIZE_256B 256
#define MEMSET_STRING(stringBuf,len){\
		memset(stringBuf, '\0', len);\
	}
#define CHECK_OUT_WATCHDOG_TIME 3 // every 3 seconds, check watchdog status, zigbee thread ever 2 seconds feed dog one times if zigbee run normal.
#define PROGRESS_GATEWAY_TIMEOUT (60/CHECK_OUT_WATCHDOG_TIME)

typedef enum 
{
	THREAD_STOP		= 0,
	THREAD_RUNNING	= 1,
	THREAD_PROGRESS = 2
}emWatchdogStatus;

int main(int argc, char const *argv[])
{
	FILE* fd;
	char getItemName[SIZE_256B] = "\0";
	int getItemValue = 0;
	int watchdogCount = 0;
	int feedDogError = 0;
	int progressGatewayTimeoutCount = 0;

	printf("\n\nLogzigbee version: %s -- %s.\n\n", __TIME__, __DATE__);
	sleep(2);  // wait zigbee running

	while (1)
	{
		printf("Start check zigbee.\n");

		system("chmod -R 777 /tmp/logZigbee.txt");
		MEMSET_STRING(getItemName,SIZE_256B)
		if ((fd = fopen("/tmp/logZigbee.txt", "r")) == NULL)
		{
			printf("open logZigbee.txt error.\n");
			//return -1;   // logzigbee never exit, because it need to restart zigbee when it be killed.
		}
		else
		{
			while (fscanf(fd, "%s %d", getItemName, &getItemValue) != EOF)
			{
				if (strcmp(getItemName, "zigbeeRunCount") == 0
					&& (getItemValue > 0))
				{
					printf("get zigbeeRunCount : %d\n", getItemValue);

					if (watchdogCount == getItemValue)
					{
						feedDogError++;
					}
					else
					{
						watchdogCount = getItemValue;
						feedDogError = 0;
					}
					
				}

				if (strcmp(getItemName, "zigbeeRunStatus") == 0)
				{
					printf("get zigbeeRunStatus : %d\n", getItemValue);

					if (getItemValue == 0 || ((getItemValue == 1) && (feedDogError >= 3)))
					{
						feedDogError = 0;
						watchdogCount = 0;
						progressGatewayTimeoutCount = 0;

						system("killall -9 tarscript.sh");
						system("killall -9 zigbee");
						system("chmod -R 777 /root/tarscript.sh");
						system("/root/tarscript.sh 4 zigbee /root/zigbee");
					}
					else if (getItemValue == 2)
					{
						if (++progressGatewayTimeoutCount >= PROGRESS_GATEWAY_TIMEOUT)
						{
							progressGatewayTimeoutCount = 0;
							getItemValue = 0;   // progress gateway error, restart zigbee
						}
					}
				}
				
				MEMSET_STRING(getItemName,SIZE_256B)
			}

			fclose(fd);
		}

		sleep(CHECK_OUT_WATCHDOG_TIME); 
	}

	return 0;
}
