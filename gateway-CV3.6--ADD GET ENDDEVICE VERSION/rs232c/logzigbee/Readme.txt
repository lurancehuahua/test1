��1�� etclogzigbee 
url��/etc/init.d/

������Ȩ��
chmod -R 777 /etc/init.d/etclogzigbee
/etc/init.d/etclogzigbee enable

���ã�����/root/logzigbee �ļ�

��2��logzigbee.c

������������룺
mipsel-openwrt-linux-musl-gcc logzigbee.c -o logzigbee

����������logzigbee ��������/root/Ŀ¼�£�������Ȩ��
chomd -R 777 /root/logzigbee

���ã�������Ź�����zigbee�쳣�˳�/����MT7688�˳�ʱ����������/root/zigbee

��3��tarscript.sh
���zigbee��logzigbeeʹ�õ�shell �ű�
���·����/root/tarscript.sh
������Ȩ����ʹ�ã�chmod -R 777 /root/tarscript.sh


��4��progressGateway.c
MT7688 �����ű�Demo

MT7688���������������Ҫ���������ű���configScript.txt�����������������ݺ�������������

��5��configScript.txt
����MT7688�������ݣ������������ڶ�JN5169�Զ������Ͳ���E2ROM�ȡ�