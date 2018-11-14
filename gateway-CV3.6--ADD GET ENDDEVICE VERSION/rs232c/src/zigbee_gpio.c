#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <zigbee.h>

// bootloader
#if 1
#define MT7688_BASE_SYSTEM_ADDR 0x10000000
#define SYSTEM_LEN    0x8000
#define DEV_MEM_CTL   "/dev/mem"
static int32 dev_mem = -1;
static uint32 *pMem_map = NULL;
#endif

#define MSG(args...) printf(args)

static int s_buttonStatus = 0;


//º¯ÊýÉùÃ÷
/*GPIO operation by memory*/
int Enter_Bootloader_mode(void);
int Leave_Bootloader_mode(void);
static int mem_open(void);
static int mmap_init(void);
static int mmap_free(void);
static void mem_close(void);
void mem_free_all(void);
int  ReadRegister(unsigned long phy_addr);
int  Register_operation(teMT7688Mode phy_addr, teRegOperation method, int wValue);

/*GPIO operation by file*/
static int gpio_export(int pin);
static int gpio_unexport(int pin);
static int gpio_direction(int pin, int dir);
static int gpio_write(int pin, int value);
static int gpio_read(int pin);

int isButtonPressed(void);
int initGpio(void);
int gpio_unusedfun(void);


int Enter_Bootloader_mode(void)
{
    int pinValue = 0;

    MSG("ENTER: %s.\n",__FUNCTION__);

    //1.set gpio41,gpio42 to gpio mode
    pinValue = Register_operation(MT7688_GPIO_MODE,READ_REG_OPERATION,0);
    pinValue = SET_SPIMISO_TO_GPIO(pinValue);
    pinValue = SET_RESET_TO_GPIO(pinValue);
    Register_operation(MT7688_GPIO_MODE,WRITE_REG_OPERATION,pinValue);

    //2.set gpio 41,gpio42 to out direction
    pinValue = Register_operation(MT7688_GPIO_DIRECTION,READ_REG_OPERATION,0);
    pinValue = SET_SPIMISO_OUTPUT_DIRECTION(pinValue);
    pinValue = SET_RESET_OUTPUT_DIRECTION(pinValue);
    Register_operation(MT7688_GPIO_DIRECTION,WRITE_REG_OPERATION,pinValue);

    //3.set gpio41,gpio42 to boodloader edge  status
    pinValue = Register_operation(MT7688_GPIO_VALUE,READ_REG_OPERATION,0);
    pinValue = SET_SPIMISO_HIGH_VALUE(pinValue);
    pinValue = SET_RESET_HIGH_VALUE(pinValue);
    Register_operation(MT7688_GPIO_VALUE,WRITE_REG_OPERATION,pinValue);
    usleep(1000*1000); //reset

    pinValue = SET_SPIMISO_LOW_VALUE(pinValue);
    Register_operation(MT7688_GPIO_VALUE,WRITE_REG_OPERATION,pinValue);
    usleep(100*1000);

    pinValue = SET_RESET_LOW_VALUE(pinValue);
    Register_operation(MT7688_GPIO_VALUE,WRITE_REG_OPERATION,pinValue);
    usleep(100*1000);

    pinValue = SET_RESET_HIGH_VALUE(pinValue);
    Register_operation(MT7688_GPIO_VALUE,WRITE_REG_OPERATION,pinValue);
    usleep(200*1000);

    MSG("Leave: %s.\n",__FUNCTION__);
    return 0;
}

int Leave_Bootloader_mode(void)
{
    int pinValue = 0;

    pinValue = Register_operation(MT7688_GPIO_VALUE,READ_REG_OPERATION,0);
    pinValue = SET_SPIMISO_HIGH_VALUE(pinValue);
    pinValue = SET_RESET_HIGH_VALUE(pinValue);
    Register_operation(MT7688_GPIO_VALUE,WRITE_REG_OPERATION,pinValue);
    usleep(500*1000);

    pinValue = SET_RESET_LOW_VALUE(pinValue);
    Register_operation(MT7688_GPIO_VALUE,WRITE_REG_OPERATION,pinValue);
    usleep(1000*1000);

    pinValue = SET_SPIMISO_HIGH_VALUE(pinValue);
    pinValue = SET_RESET_HIGH_VALUE(pinValue);
    Register_operation(MT7688_GPIO_VALUE,WRITE_REG_OPERATION,pinValue);

    mem_free_all();
    MSG("Leave: %s.\n",__FUNCTION__);
    return 0;
}

int  Register_operation(teMT7688Mode phy_addr, teRegOperation method, int wValue)
{
    int regValue = 0;

    if(dev_mem < 0)
    {
        if(mem_open() < 0)
        {
            printf("open memory error!\n");
            return -1;
        }
    }

    if(pMem_map == NULL)
    {
        if(mmap_init() < 0)
        {
            printf("mmap init error!\n");
            return -1;
        }
    }

    if (method == READ_REG_OPERATION)
    {
        regValue = READ_REG(pMem_map,phy_addr);
        printf("Raddr: 0x%08x , value: %08x \n", phy_addr, regValue);
        return regValue;
    }
    else if(method == WRITE_REG_OPERATION)
    {
        WRITE_REG(pMem_map,phy_addr,wValue);
        printf("Raddr: 0x%08x , value: %08x \n", phy_addr, READ_REG(pMem_map,phy_addr));
    }

    return 0;
}


static int mmap_init(void)
{
    unsigned long phyaddr = MT7688_BASE_SYSTEM_ADDR;
    if(pMem_map == NULL)
    {
        pMem_map = mmap((void *)phyaddr, SYSTEM_LEN, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED,
                        dev_mem, phyaddr);
        if(pMem_map != (void *)phyaddr)
        {
            printf("mem failed/n");
            return -1;
        }
    }

    return 0;
}

static int mem_open(void)
{
    if(dev_mem < 0)
    {
        dev_mem = open(DEV_MEM_CTL, O_RDWR|O_SYNC);

        if(dev_mem < 0)
        {
            printf("open %s error/n", DEV_MEM_CTL);
            return -1;
        }
    }
    return 0;
}

static int mmap_free(void)
{
    if(pMem_map)
    {
        munmap(pMem_map, SYSTEM_LEN);
        pMem_map = NULL;
    }
	return 0;
}
static void mem_close(void)
{
    if(dev_mem > 0)
    {
        close(dev_mem);
        dev_mem = -1;
    }
}

void mem_free_all(void)
{
    mmap_free();
    mem_close();
}



int gpio_unusedfun(void);

//used to remove compile warnings
int gpio_unusedfun(void)
{
    gpio_write(0, 0);
    gpio_read(0);
    gpio_unexport(11);

    return 0;
}


static int gpio_export(int pin)
{
    char buffer[64];
    int len;
    int fd;

    fd = open("/sys/class/gpio/export", O_WRONLY);
    if (fd < 0)
    {
        MSG("Failed to open export for writing!\n");
        return(-1);
    }

    len = snprintf(buffer, sizeof(buffer), "%d", pin);
    if (write(fd, buffer, len) < 0)
    {
        MSG("Failed to export gpio!");
        return -1;
    }

    close(fd);
    return 0;
}


static int gpio_unexport(int pin)
{
    char buffer[64];
    int len;
    int fd;

    fd = open("/sys/class/gpio/unexport", O_WRONLY);
    if (fd < 0)
    {
        MSG("Failed to open unexport for writing!\n");
        return -1;
    }

    len = snprintf(buffer, sizeof(buffer), "%d", pin);
    if (write(fd, buffer, len) < 0)
    {
        MSG("Failed to unexport gpio!");
        return -1;
    }

    close(fd);
    return 0;
}

//dir: 0-->IN, 1-->OUT
static int gpio_direction(int pin, int dir)
{
    static const char dir_str[] = "in\0out";
    char path[64];
    int fd;

    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/direction", pin);
    fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        MSG("Failed to open gpio direction for writing!\n");
        return -1;
    }

    if (write(fd, &dir_str[dir == 0 ? 0 : 3], dir == 0 ? 2 : 3) < 0)
    {
        MSG("Failed to set direction!\n");
        return -1;
    }

    close(fd);
    return 0;
}

//value: 0-->LOW, 1-->HIGH
static int gpio_write(int pin, int value)
{
    static const char values_str[] = "01";
    char path[64];
    int fd;

    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/value", pin);
    fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        MSG("Failed to open gpio value for writing!\n");
        return -1;
    }

    if (write(fd, &values_str[value == 0 ? 0 : 1], 1) < 0)
    {
        MSG("Failed to write value!\n");
        return -1;
    }

    close(fd);
    return 0;
}

static int gpio_read(int pin)
{
    char path[64];
    char value_str[3];
    int fd;

    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/value", pin);
    fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        MSG("Failed to open gpio value for reading!\n");
        return -1;
    }

    if (read(fd, value_str, 3) < 0)
    {
        MSG("Failed to read value!\n");
        return -1;
    }

    close(fd);
    return (atoi(value_str));
}


// 0-->none, 1-->rising, 2-->falling, 3-->both
static int gpio_edge(int pin, int edge)
{
    const char dir_str[] = "none\0rising\0falling\0both";
    char path[64];
    int fd, ptr;

    switch(edge)
    {
    case 0:
        ptr = 0;
        break;
    case 1:
        ptr = 5;
        break;
    case 2:
        ptr = 12;
        break;
    case 3:
        ptr = 20;
        break;
    default:
        ptr = 0;
    }

    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/edge", pin);
    fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        MSG("Failed to open gpio edge for writing!\n");
        return -1;
    }

    if (write(fd, &dir_str[ptr], strlen(&dir_str[ptr])) < 0)
    {
        MSG("Failed to set edge!\n");
        return -1;
    }

    close(fd);
    return 0;
}


//GPIO1_17
static void gpio_process(void)
{
    int gpio_fd, ret;
    struct pollfd fds[1];
    char buff[10];

    //init LED gpio
    //gpio_export(115);
    //gpio_direction(115, 1);
    //gpio_write(115, 0);

    //init key gpio
    gpio_export(11);
    gpio_direction(11, 0);
    gpio_edge(11,1);

    gpio_fd = open("/sys/class/gpio/gpio11/value",O_RDONLY);
    if(gpio_fd < 0)
    {
        MSG("Failed to open value!\n");
        return;
    }

    fds[0].fd = gpio_fd;
    fds[0].events  = POLLPRI;
    ret = read(gpio_fd,buff,10);
    if( ret == -1 )
        MSG("read\n");

    while(1)
    {
        ret = poll(fds,1,0);
        if( ret == -1 )
            MSG("poll\n");
        if( fds[0].revents & POLLPRI)
        {
            ret = lseek(gpio_fd,0,SEEK_SET);
            if( ret == -1 )
                MSG("lseek\n");

            ret = read(gpio_fd,buff,10);
            if( ret == -1 )
                MSG("read\n");
            MSG("---------------Button pressed-------------\n");

            s_buttonStatus = 1;
            //gpio_write(115, cnt++%2);
        }
        usleep(100000);
    }
    return;
}


int isButtonPressed(void)
{
    MSG("Enter: %s, %d\n", __FUNCTION__, __LINE__);

    s_buttonStatus = 0;

    while(1)
    {
        usleep(100000);
        if (s_buttonStatus == 1)
        {
            MSG("Leave: %s, %d\n", __FUNCTION__, __LINE__);
            return 1;
        }
    }
    MSG("Leave: %s, %d\n", __FUNCTION__, __LINE__);
    return 0;
}


int initGpio(void)
{
    int ret;
    pthread_t pThreadGpioId;

    MSG("Enter: %s, %d\n", __FUNCTION__, __LINE__);

    ret = pthread_create(&pThreadGpioId, NULL, (void*)gpio_process, NULL);
    if(ret != 0)
    {
        MSG("create gpio_process thread error\n");
        return 1;
    }

    MSG("Leave: %s, %d\n", __FUNCTION__, __LINE__);

    return 0;
}
