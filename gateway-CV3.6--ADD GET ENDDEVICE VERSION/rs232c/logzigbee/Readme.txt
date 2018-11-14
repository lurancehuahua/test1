【1】 etclogzigbee 
url：/etc/init.d/

需设置权限
chmod -R 777 /etc/init.d/etclogzigbee
/etc/init.d/etclogzigbee enable

作用：启动/root/logzigbee 文件

【2】logzigbee.c

编译服务器编译：
mipsel-openwrt-linux-musl-gcc logzigbee.c -o logzigbee

将编译结果：logzigbee 放在网关/root/目录下，并设置权限
chomd -R 777 /root/logzigbee

作用：软件看门狗，当zigbee异常退出/升级MT7688退出时，重新启动/root/zigbee

【3】tarscript.sh
配合zigbee、logzigbee使用的shell 脚本
存放路径：/root/tarscript.sh
需设置权限再使用：chmod -R 777 /root/tarscript.sh


【4】progressGateway.c
MT7688 升级脚本Demo

MT7688升级软件包，必须要包含升级脚本和configScript.txt，用来处理升级内容和配置升级内容

【5】configScript.txt
配置MT7688升级内容，包括但不限于对JN5169自动升级和擦除E2ROM等。