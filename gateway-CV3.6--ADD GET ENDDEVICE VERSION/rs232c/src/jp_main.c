/****************************************************************************
*
* MODULE:             Jennic Module Programmer
*
* COMPONENT:          Main file
*
* VERSION:            $Name:  $
*
* REVISION:           $Revision: 1.2 $
*
* DATED:              $Date: 2009/03/02 13:33:44 $
*
* STATUS:             $State: Exp $
*
* AUTHOR:             Matt Redfearn
*
* DESCRIPTION:
*
*
* LAST MODIFIED BY:   $Author: lmitch $
*                     $Modtime: $
*
****************************************************************************
*
* This software is owned by NXP B.V. and/or its supplier and is protected
* under applicable copyright laws. All rights are reserved. We grant You,
* and any third parties, a license to use this software solely and
* exclusively on NXP products [NXP Microcontrollers such as JN5148, JN5142, JN5139]. 
* You, and any third parties must reproduce the copyright and warranty notice
* and any other legend of ownership on each copy or partial copy of the 
* software.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.

* Copyright NXP B.V. 2012. All rights reserved
*
***************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>

#include "JN51xx_BootLoader.h"
#include "Firmware.h"
#include "uart.h"
#include "ChipID.h"
#include "dbg.h"
#include "newLog.h"

// #define LL_LOG( t )
#define LL_LOG( t ) filelog( "/tmp/log/flasher.log", t )

#define vDelay(a) usleep(a * 1000)

int iVerbosity = 1;

/** Import binary data from FlashProgrammerExtension_JN5168.bin */
int _binary_FlashProgrammerExtension_JN5168_bin_start;
int _binary_FlashProgrammerExtension_JN5168_bin_size;
int _binary_FlashProgrammerExtension_JN5169_bin_start;
int _binary_FlashProgrammerExtension_JN5169_bin_size;
int _binary_FlashProgrammerExtension_JN5179_bin_start;
int _binary_FlashProgrammerExtension_JN5179_bin_size;

char * flashExtension = NULL;

//const char *cpSerialDevice = "/dev/ttyUSB0";
const char *cpSerialDevice = "/dev/ttyS1";
//const char *pcFirmwareFile = "/tmp/ZigbeeNodeControlBridge_JN5169.bin";
//const char *pcFirmwareFile = NULL;

char *pcMAC_Address = NULL;
uint64_t u64MAC_Address;
uint64_t *pu64MAC_Address = NULL;

int iInitialSpeed=57600;
int iProgramSpeed=57600;//1000000;

teStatus cbProgress(void *pvUser, const char *pcTitle, const char *pcText, int iNumSteps, int iProgress)
{
    int progress;
    if (iNumSteps > 0)
    {
        progress = ((iProgress * 100) / iNumSteps);
    }
    else
    {
        // Begin marker
        progress = 0;
        printf( "\n" );
    }
    printf( "%c[A%s = %d%%\n", 0x1B, pcText, progress );
        
    return E_PRG_OK;
}

static int importExtension( char * file, int * start, int * size ) {
    struct stat sb;
    if (stat(file, &sb) == -1) {
        perror("stat");
        return 0;
    }
    
    printf("File size: %lld bytes\n", (long long) sb.st_size);
    size_t bytestoread = sb.st_size;
    
    if ( ( flashExtension = malloc( sb.st_size + 100 ) ) == NULL ) {
        perror("malloc");
        return 0;
    }
    
    int fp, bytesread;
    if ( ( fp = open(file,O_RDONLY) ) < 0 ) {
        perror("open");
        return 0;
    }
    
    char * pbuf = flashExtension;
    while ( bytestoread > 0 ) {
        if ( ( bytesread = read( fp, pbuf, bytestoread ) ) < 0 ) {
            break;
        }
        bytestoread -= bytesread;
        pbuf += bytesread;
        }
        
    if ( bytestoread == 0 ) {
        *start = (int)flashExtension;
        *size  = sb.st_size;
        printf( "Loaded binary of %d bytes\n", *size );
        return 1;
    }
    
    return 0;
}

static teStatus ePRG_ImportExtension(tsPRG_Context *psContext)
{
    int ret = 0;

    switch (CHIP_ID_PART(psContext->sChipDetails.u32ChipId))
    {
        case (CHIP_ID_PART(CHIP_ID_JN5168)):
            //ret = importExtension( "/usr/share/iot/FlashProgrammerExtension_JN5168.bin",
            ret = importExtension( "/usr/lib/iot/FlashProgrammerExtension_JN5168.bin",
                &_binary_FlashProgrammerExtension_JN5168_bin_start,
                &_binary_FlashProgrammerExtension_JN5168_bin_size );
            psContext->pu8FlashProgrammerExtensionStart    = (uint8_t *)_binary_FlashProgrammerExtension_JN5168_bin_start;
            psContext->u32FlashProgrammerExtensionLength   = (uint32_t)_binary_FlashProgrammerExtension_JN5168_bin_size;
            break;
        case (CHIP_ID_PART(CHIP_ID_JN5169)):
            //ret = importExtension( "/usr/share/iot/FlashProgrammerExtension_JN5169.bin",
            ret = importExtension( "/usr/lib/iot/FlashProgrammerExtension_JN5169.bin",
                &_binary_FlashProgrammerExtension_JN5169_bin_start,
                &_binary_FlashProgrammerExtension_JN5169_bin_size );
            psContext->pu8FlashProgrammerExtensionStart    = (uint8_t *)_binary_FlashProgrammerExtension_JN5169_bin_start;
            psContext->u32FlashProgrammerExtensionLength   = (uint32_t)_binary_FlashProgrammerExtension_JN5169_bin_size;
            break;
        case (CHIP_ID_PART(CHIP_ID_JN5179)):
            //ret = importExtension( "/usr/share/iot/FlashProgrammerExtension_JN5179.bin",
            ret = importExtension( "/usr/lib/iot/FlashProgrammerExtension_JN5179.bin",
                &_binary_FlashProgrammerExtension_JN5179_bin_start,
                &_binary_FlashProgrammerExtension_JN5179_bin_size );
            psContext->pu8FlashProgrammerExtensionStart    = (uint8_t *)_binary_FlashProgrammerExtension_JN5179_bin_start;
            psContext->u32FlashProgrammerExtensionLength   = (uint32_t)_binary_FlashProgrammerExtension_JN5179_bin_size;
            break;
    }
    if ( ret ) {
        return E_PRG_OK;
    }
        
    return E_PRG_ERROR;
}


int JennicModuleProgrammer(const char *pcFirmwareFile, int clearE2ROMFlag)
{
    tsPRG_Context   sPRG_Context;
    int ret = 0;
    int iVerify = 1;

    printf("JennicModuleProgrammer Version: v1.0.0\n");
    
    memset(&sPRG_Context, 0, sizeof(tsPRG_Context));
    
    if (eUART_Initialise((char *)cpSerialDevice, iInitialSpeed, &sPRG_Context.iUartFD, &sPRG_Context.sUartOptions) != E_PRG_OK)
    {
        fprintf(stderr, "Error opening serial port\n");
        LL_LOG( "Error opening serial port" );
        return -1;
    }
    //LL_LOG( "Serial port opened at iInitialSpeed (= 38400)" );

	printf("function:%s line:%d\n", __FUNCTION__, __LINE__);

    if (iInitialSpeed != iProgramSpeed)
    {
    	printf("function:%s line:%d\n", __FUNCTION__, __LINE__);
        if (iVerbosity > 1)
        {
            printf("Setting baudrate for port %d to %d\n", sPRG_Context.iUartFD, iProgramSpeed);
        }

        /* Talking at initial speed - change bootloader to programming speed */
        int retry = 3;
		int testFlag = 0;
        while ( retry-- > 0) {
			testFlag = eBL_SetBaudrate(&sPRG_Context, iProgramSpeed);
			printf("%s %d,eBL_SetBaudrate return value:%d\n",__FUNCTION__, __LINE__, testFlag);
			if (testFlag != E_PRG_OK)
			{
				printf("Error setting (bootloader) baudrate to iProgramSpeed (%d) (%d)\n", iProgramSpeed, retry);
	            LL_LOG( "Error setting (bootloader) baudrate to iProgramSpeed (= 1000000)" );
	            // ret = 2;
	            //continue;
			}
			//break;
        }
		
		printf("function:%s line:%d\n", __FUNCTION__, __LINE__);
        if ( retry <= 0 ) ret = 2;
        /* change local port to programming speed */
		
        if (eUART_SetBaudRate(sPRG_Context.iUartFD, &sPRG_Context.sUartOptions, iProgramSpeed) != E_PRG_OK)
        {
            printf("Error setting (local port) baudrate to iProgramSpeed (%d)\n", iProgramSpeed);
            LL_LOG( "Error setting (local port) baudrate to iProgramSpeed" );
            // eBL_SetBaudrate(&sPRG_Context, iInitialSpeed );
            ret = 3;
        }
    }
	
	printf("function:%s line:%d\n", __FUNCTION__, __LINE__);
   // ret = 0;
    if ( ret != 0 ) return -1;

    /* Read module details at initial baud rate */
    if (ePRG_ChipGetDetails(&sPRG_Context) != E_PRG_OK)
    {
        fprintf(stderr, "Error reading module information - check cabling and power\n");
        LL_LOG( "Error reading module information - check cabling and power" );
        ret = 4;
    }
	printf("function:%s line:%d\n", __FUNCTION__, __LINE__);
    if ( ret == 0 && iVerbosity > 0)
    {
    	printf("function:%s line:%d\n", __FUNCTION__, __LINE__);
        const char *pcPartName;
        
        switch (sPRG_Context.sChipDetails.u32ChipId)
        {
            case (CHIP_ID_JN5148_REV2A):    pcPartName = "JN5148";      break;
            case (CHIP_ID_JN5148_REV2B):    pcPartName = "JN5148";      break;
            case (CHIP_ID_JN5148_REV2C):    pcPartName = "JN5148";      break;
            case (CHIP_ID_JN5148_REV2D):    pcPartName = "JN5148J01";   break;
            case (CHIP_ID_JN5148_REV2E):    pcPartName = "JN5148Z01";   break;

            case (CHIP_ID_JN5142_REV1A):    pcPartName = "JN5142";      break;
            case (CHIP_ID_JN5142_REV1B):    pcPartName = "JN5142";      break;
            case (CHIP_ID_JN5142_REV1C):    pcPartName = "JN5142J01";   break;

            case (CHIP_ID_JN5168):          pcPartName = "JN5168";      break;
            case (CHIP_ID_JN5168_COG07A):   pcPartName = "JN5168";      break;
            case (CHIP_ID_JN5168_COG07B):   pcPartName = "JN5168";      break;
            
            case (CHIP_ID_JN5169):          pcPartName = "JN5169";      break;
            case (CHIP_ID_JN5169_DONGLE):   pcPartName = "JN5169";      break;

            case (CHIP_ID_JN5172):          pcPartName = "JN5172";      break;

            case (CHIP_ID_JN5179):          pcPartName = "JN5179";      break;

            default:                        pcPartName = "Unknown";     break;
        }

        printf("Detected Chip: %s\n", pcPartName);
        
        printf("MAC Address:   %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n", 
                sPRG_Context.sChipDetails.au8MacAddress[0] & 0xFF, 
                sPRG_Context.sChipDetails.au8MacAddress[1] & 0xFF, 
                sPRG_Context.sChipDetails.au8MacAddress[2] & 0xFF, 
                sPRG_Context.sChipDetails.au8MacAddress[3] & 0xFF, 
                sPRG_Context.sChipDetails.au8MacAddress[4] & 0xFF, 
                sPRG_Context.sChipDetails.au8MacAddress[5] & 0xFF, 
                sPRG_Context.sChipDetails.au8MacAddress[6] & 0xFF, 
                sPRG_Context.sChipDetails.au8MacAddress[7] & 0xFF);
    }

    ret = 0;
    //if (ret == 0 && pcFirmwareFile)
    {
        /* Have file to program */
    	printf("function:%s line:%d\n", __FUNCTION__, __LINE__);
        if (ePRG_FwOpen(&sPRG_Context, (char *)pcFirmwareFile)) 
        {
            /* Error with file. FW module has displayed error so just exit. */
            LL_LOG( "Error with firmware file" );
            ret = 5;
        }

        printf("ePRG_FwOpen Line = %d\n", __LINE__);

#if 0
		printf("\n\n************************************\n");

		printf("ChipData:\n");
		printf("sPRG_Context.sChipDetails.u32ChipId: %d\n", sPRG_Context.sChipDetails.u32ChipId);
		printf("sPRG_Context.sChipDetails.u32SupportedFirmware: %d\n", sPRG_Context.sChipDetails.u32SupportedFirmware);
		printf("sPRG_Context.sChipDetails.u32NumFlashes: %d\n", sPRG_Context.sChipDetails.u32NumFlashes);
		printf("sPRG_Context.sChipDetails.u32EepromSize: %d\n", sPRG_Context.sChipDetails.u32EepromSize);
		printf("sPRG_Context.sChipDetails.u32BootloaderVersion: %d\n", sPRG_Context.sChipDetails.u32BootloaderVersion);
		printf("sPRG_Context.sChipDetails.asFlashes->u32FlashSize: %d\n", sPRG_Context.sChipDetails.asFlashes->u32FlashSize);
		printf("sPRG_Context.sChipDetails.asFlashes->u8ManufacturerID: %d\n", sPRG_Context.sChipDetails.asFlashes->u8ManufacturerID);
		printf("sPRG_Context.sChipDetails.asFlashes->u8DeviceID: %d\n", sPRG_Context.sChipDetails.asFlashes->u8DeviceID);
		printf("sPRG_Context.sChipDetails.asFlashes->u32FlashSize: %d\n", sPRG_Context.sChipDetails.asFlashes->u32FlashSize);
		
		printf("FWData:\n");
		printf("sPRG_Context.u32FirmWareFileSize: %d\n", sPRG_Context.u32FirmWareFileSize);
		printf("sPRG_Context.sFirmwareInfo.u32ROMVersion: %d\n", sPRG_Context.sFirmwareInfo.u32ROMVersion);
		printf("sPRG_Context.sFirmwareInfo.u32ImageLength: %d\n", sPRG_Context.sFirmwareInfo.u32ImageLength);
		
		printf("\n\n************************************\n");

#endif
		

        if (ret == 0)
        {
            if ( ePRG_FlashProgram(&sPRG_Context, cbProgress, NULL, NULL) != E_PRG_OK )
            {
            LL_LOG( "Error with flashing" );
            ret = 6;
            }
			printf("ePRG_FlashProgram successful.\n");
        }
        
        printf("ePRG_FlashProgram Line = %d\n", __LINE__);
        
        if (ret == 0)
        {
            if ( iVerify && ePRG_FlashVerify(&sPRG_Context, cbProgress, NULL) != E_PRG_OK )
            {
            LL_LOG( "Error in verification" );
            ret = 7;
        	}
			printf("ePRG_FlashVerify successful.\n");
        }
        
        printf("ePRG_FlashVerify Line = %d\n", __LINE__);

        if (ret == 0)
        {
            if ( ePRG_ImportExtension(&sPRG_Context) != E_PRG_OK )
            {
                LL_LOG( "Error importing extension" );
                ret = 8;
            }
			printf("ePRG_ImportExtension successful.\n");
        }
       
        printf("ePRG_ImportExtension Line = %d\n", __LINE__);
       
#if 1
        if ( ret == 0 && clearE2ROMFlag == 1) 
        {
            if ( ePRG_EepromErase(&sPRG_Context, E_ERASE_EEPROM_PDM, cbProgress, NULL) != E_PRG_OK) 
            {
                LL_LOG( "Error erasing EEPROM" );
                ret = 9;
            }
			printf("ePRG_EepromErase successful.\n");
        }
#endif

        printf("ePRG_EepromErase Line = %d\n", __LINE__);
    }
    
    // Set BL and local port back to initial speed (in reverse order)
   // eBL_SetBaudrate(&sPRG_Context, iInitialSpeed);
    eBL_SetBaudrate(&sPRG_Context, 115200);
	printf("function:%s line:%d\n", __FUNCTION__, __LINE__);
    //eUART_SetBaudRate(sPRG_Context.iUartFD, &sPRG_Context.sUartOptions, iInitialSpeed);
    eUART_SetBaudRate(sPRG_Context.iUartFD, &sPRG_Context.sUartOptions, 115200);
    printf("function:%s line:%d\n", __FUNCTION__, __LINE__);
    if ( ret == 0 && iVerbosity > 0) {
        printf("Success\n");
		return 1;
    }
    return -1;
}

