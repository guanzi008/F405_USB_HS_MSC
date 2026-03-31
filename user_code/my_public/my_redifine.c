#include <stdio.h>
#include <time.h>

#include "rtc.h"




#include "my_redifine.h"



/* 输出重定向 printf */
 
#ifdef __GNUC__
/* With GCC, small printf (option LD Linker->Libraries->Small printf
   set to 'Yes') calls __io_putchar() */
#define PUTCHAR_PROTOTYPE int __io_putchar(int ch)
#else
#define PUTCHAR_PROTOTYPE int fputc(int ch, FILE *f)
#endif /* __GNUC__ */
 
PUTCHAR_PROTOTYPE
{
    HAL_UART_Transmit(&THE_DEBUG_UART_HAND, (uint8_t *)&ch, 1, 0xFFFF);
 
    return ch;
}
 
int _write(int file, char *ptr, int len)
{
    int DataIdx;
 
    for (DataIdx = 0; DataIdx < len; DataIdx++) {
        __io_putchar(*ptr++);
    }
    return len;
}

/*以上为 输出重定向 printf*/



void printInit(void)
{
    THE_DEBUG_UART_INIT();
}






/**
 * @brief 重定义time函数
 * 
 * @param _timer 
 * @return time_t 
 * @note 实际上每次都调用RTC中的函数
 */
time_t time (time_t *_timer)
{
  time_t result;

  RTC_TimeTypeDef theRTCtime = {0X00};
  RTC_DateTypeDef theRTCdate = {0X00};
  HAL_RTC_GetTime(&hrtc, &theRTCtime, RTC_FORMAT_BIN);
  HAL_RTC_GetDate(&hrtc, &theRTCdate, RTC_FORMAT_BIN);

  struct tm tem = {0X00};
  // 转为秒数以设定time_dat
  tem.tm_year = theRTCdate.Year + 2000 - 1900;
  tem.tm_mon  = theRTCdate.Month  - 1;
  tem.tm_mday = theRTCdate.Date;
  tem.tm_hour = theRTCtime.Hours;
  tem.tm_min  = theRTCtime.Minutes;
  tem.tm_sec  = theRTCtime.Seconds;

  result = mktime(&tem);//转为秒并设定
  
  if(_timer != NULL)
  {
    *_timer = result;
  }
  return result;
}
