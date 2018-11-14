#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DBG(...)   printf(__VA_ARGS__)

/*
*	system() return 0, is do shell ok.
*/

/*
*	start thread demo:  /root/zigbee  
*	stop thread demo:  killall -9 zigbee
*/

/*
*	copy file demo: cp /productDemo.htm /root/
*	delete file demo: rm /root/productDemo.htm
*	modify jurisdiction: chmod -R 777 /productDemo.htm
*/

/*
*	 update file progress:
*	1. modify file jurisdiction
*	2. cp filt to dst
*	3. modify dst file jurisdiction
*
*	Note: zigbee thread control more file, so we should kill zigbee thread first, 
*		  and then, restart zigbee in the end.
*/

int main()
{
	int ret;

	system("killall -9 zigbee");

	system("chmod -R 777 /root/progressMT7688/zigbee");
	system("chmod -R 777 /root/progressMT7688/ZigbeeNodeControlBridge_JN5169.bin");
	system("chmod -R 777 /root/progressMT7688/progressGateway");

	system("cp /root/progressMT7688/zigbee /root/");
	system("cp /root/progressMT7688/ZigbeeNodeControlBridge_JN5169.bin /usr/lib/iot/");

	system("chmod -R 777 /root/zigbee");
	system("chmod -R 777 /usr/lib/iot/ZigbeeNodeControlBridge_JN5169.bin");
		
	system("/root/zigbee");   // care : zigbee thread start later need to kill update script
	return 0;
}
