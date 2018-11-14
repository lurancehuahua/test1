
/****************************************************************************
 *
 * MODULE:             Jennic Module Programmer
 *
 * COMPONENT:          Serial port handling
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
/****************************************************************************/
/***        Include files                                                 ***/
/****************************************************************************/

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
//#include <fcntl.h>
#include <string.h>
#include <termios.h>

#include <sys/select.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <errno.h>

#include <linux/types.h>

#include "rs232.h"

#include "programmer.h"
#include "uart.h"
#include "dbg.h"

#define MAX_ERROR_STRING_LEN

/****************************************************************************/
/***        Macro Definitions                                             ***/
/****************************************************************************/

#ifdef DEBUG_UART
#define TRACE_UART	TRUE
#else
#define TRACE_UART	FALSE
#endif

extern struct rs232_port_t *s_pst232port;

/****************************************************************************/
/***        Type Definitions                                              ***/
/****************************************************************************/

/****************************************************************************/
/***        Local Function Prototypes                                     ***/
/****************************************************************************/

/****************************************************************************/
/***        Exported Variables                                            ***/
/****************************************************************************/

/****************************************************************************/
/***        Local Variables                                               ***/
/****************************************************************************/

/****************************************************************************/
/***        Exported Functions                                            ***/
/****************************************************************************/
/****************************************************************************
 *
 * NAME: UART_eInitialise
 *
 * DESCRIPTION:
 * Initialise a UART
 *
 * RETURNS:
 * teStatus
 *
 ****************************************************************************/
 
teStatus eUART_Initialise(char *pcDevice, int iBaudRate, int *piFileDescriptor, struct termios *psOptions)
{
    DBG_vPrintf(TRACE_UART, "Using UART device %s\n", pcDevice);

    if (s_pst232port == NULL) 
    {
        DBG_vPrintf(TRACE_UART, "Failed to open device!\n", pcDevice);
        return E_PRG_FAILED_TO_OPEN_FILE;
    }
    
    *piFileDescriptor = (int)s_pst232port;
	printf("#---> %s %d\n",__FUNCTION__, __LINE__);
	printf("(int)s_pst232port = %d\n", *piFileDescriptor);
	//return E_PRG_OK;
    return eUART_SetBaudRate(*piFileDescriptor, psOptions, iBaudRate);
}
 
 
/****************************************************************************
 *
 * NAME: UART_eClose
 *
 * DESCRIPTION:
 * Close the specified UART
 *
 * RETURNS:
 * teStatus
 *
 ****************************************************************************/
teStatus eUART_Close(int iFileDescriptor)
{
    return E_PRG_OK;
}


/****************************************************************************
 *
 * NAME: UART_eSetBaudRate
 *
 * DESCRIPTION:
 * Sets the baud rate of the specified UART
 *
 * RETURNS:
 * teStatus
 *
 ****************************************************************************/
teStatus eUART_SetBaudRate(int iFileDescriptor, struct termios *psOptions, int iBaudRate)
{
    int iBaud;
    
    DBG_vPrintf(TRACE_UART, "Changing baud rate to %d\n", iBaudRate);

    switch (iBaudRate)
    {
    case 38400:     iBaud = RS232_BAUD_38400;
    	break;

    case 115200:    iBaud = RS232_BAUD_115200;
		break;

    case 460800:    iBaud = RS232_BAUD_460800;
		break;

	case 1000000:    iBaud = RS232_BAUD_1000000;
		break;

    default:
        DBG_vPrintf(TRACE_UART, "Unsupported baud rate: %d, set to default 115200\n", iBaudRate);
        iBaud = RS232_BAUD_38400;
        break;
    }       
    
    rs232_set_baud(s_pst232port, iBaud);
    
    return E_PRG_OK;
}


/****************************************************************************
 *
 * NAME: UART_eFlush
 *
 * DESCRIPTION:
 * Flush the specified UART
 *
 * RETURNS:
 * teStatus
 *
 ****************************************************************************/
teStatus eUART_Flush(int iFileDescriptor)
{
	uint8_t u8Data;
	int iBytesRead;

    do
    {
        eUART_Read(iFileDescriptor, 100, 1, &u8Data, &iBytesRead);
    } while(iBytesRead > 0);


	return E_PRG_OK;
}

#define UART_DBG(...)   printf(__VA_ARGS__)

#define DUMP_BUFFER(BUFFER, BUFFER_LEN) \
do { \
    unsigned int nIndex; \
    UART_DBG("Dump Buffer, len = %d\n", BUFFER_LEN); \
    for (nIndex=0; nIndex<BUFFER_LEN; nIndex++) \
    { \
        UART_DBG("0x%02x ", BUFFER[nIndex]); \
    } \
    UART_DBG("\n"); \
}while(0);



/****************************************************************************
 *
 * NAME: UART_eRead
 *
 * DESCRIPTION:
 * Reads from the specified UART
 *
 * RETURNS:
 * teStatus
 *
 ****************************************************************************/
teStatus eUART_Read(int iFileDescriptor, int iTimeoutMicroseconds, int iBufferLen, uint8_t *pu8Buffer, int *piBytesRead)
{
    if(pu8Buffer == NULL)
    {
        return E_PRG_NULL_PARAMETER;
    }
    
    *piBytesRead = 0;

    rs232_read_timeout(s_pst232port, pu8Buffer, iBufferLen, (unsigned int *)piBytesRead, iTimeoutMicroseconds/1000);
    //rs232_read(s_pst232port, pu8Buffer, iBufferLen, piBytesRead);
    DUMP_BUFFER(pu8Buffer, *piBytesRead);
    
    return E_PRG_OK;
}
 

/****************************************************************************
 *
 * NAME: UART_eWrite
 *
 * DESCRIPTION:
 * Write to the specified UART
 *
 * RETURNS:
 * teStatus
 *
 ****************************************************************************/
teStatus eUART_Write(int iFileDescriptor, uint8_t *pu8Data, int iLength)
{
    unsigned int iBytesWritten;

    rs232_write(s_pst232port, pu8Data, iLength,&iBytesWritten);

    UART_DBG("total len: %d, written len: %d \n", iLength, iBytesWritten);
    DUMP_BUFFER(pu8Data, iLength);

    return E_PRG_OK;
}


/****************************************************************************/
/***        Local Functions                                               ***/
/****************************************************************************/

/****************************************************************************/
/***        END OF FILE                                                   ***/
/****************************************************************************/
