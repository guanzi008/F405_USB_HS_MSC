/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2024 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "usart.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdio.h>
#include "usb_device.h"
#include "my_redifine.h"
#include "usbd_conf.h"
#include "usbd_core.h"
#include "usbd_ctap_min.h"
#include "usbd_fido_class.h"
#include "aux_inputs.h"
#include "ext_flash_w25q.h"
#include "lcd_status.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
extern USBD_HandleTypeDef hUsbDeviceHS;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_UART4_Init();
  /* USER CODE BEGIN 2 */

  puts("A actual-board USB test");
  printf("%s编译时间 %s %s\n", __FILE__, __DATE__, __TIME__);

  ext_flash_init();

  if(My_USB_HS_HID_MSC_Init() != USBD_OK)
  {
    puts("usb hs hid+msc init fail");
  }
  aux_inputs_init();
  lcd_status_init();
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */

  while (1)
  {
    static uint32_t last_log_ms = 0;
    static int32_t last_menu_encoder_position = 0;
    aux_inputs_status_t aux_status;
    ext_flash_info_t flash_info;
    usbd_ctap_min_ui_status_t fido_ui;
    uint32_t input_events;
    uint32_t now = HAL_GetTick();
    uint8_t uart_rx = 0u;

    input_events = aux_inputs_poll(now);
    if (HAL_UART_Receive(&huart4, &uart_rx, 1u, 0u) == HAL_OK)
    {
      if ((uart_rx == 'y') || (uart_rx == 'Y'))
      {
        usbd_ctap_min_note_user_presence();
      }
      else if ((uart_rx == 'n') || (uart_rx == 'N'))
      {
        usbd_ctap_min_note_user_denied();
      }
    }
    if ((input_events & AUX_INPUT_EVENT_BTN_SHORT) != 0u)
    {
      usbd_ctap_min_get_ui_status(&fido_ui);
      if (fido_ui.ui_state == USBD_CTAP_UI_WAIT_TOUCH)
      {
        usbd_ctap_min_note_user_presence();
      }
      else
      {
        lcd_status_confirm();
      }
    }
    if ((input_events & AUX_INPUT_EVENT_BTN_LONG) != 0u)
    {
      usbd_ctap_min_get_ui_status(&fido_ui);
      if (fido_ui.ui_state == USBD_CTAP_UI_WAIT_TOUCH)
      {
        usbd_ctap_min_note_user_denied();
      }
      else
      {
        lcd_status_back();
      }
    }
    aux_inputs_get_status(&aux_status);
    if (lcd_status_is_menu_active() != 0u)
    {
      int32_t menu_position = aux_status.encoder_position / 2;

      while (menu_position > last_menu_encoder_position)
      {
        lcd_status_next_page();
        last_menu_encoder_position += 1;
      }
      while (menu_position < last_menu_encoder_position)
      {
        lcd_status_prev_page();
        last_menu_encoder_position -= 1;
      }
    }
    else
    {
      last_menu_encoder_position = aux_status.encoder_position / 2;
    }
    ext_flash_get_info(&flash_info);
    a_usb_diag_capture_registers();
    usbd_ctap_min_get_ui_status(&fido_ui);
    USBD_FIDO_Service(&hUsbDeviceHS, now);
    lcd_status_update((uint8_t)hUsbDeviceHS.dev_state,
                      (uint8_t)hUsbDeviceHS.dev_config,
                      g_a_usb_diag_runtime.reset_count,
                      g_a_usb_diag_runtime.setup_count,
                      g_a_usb_diag_runtime.data_out_count,
                      g_a_usb_diag_runtime.data_in_count,
                      g_a_usb_diag_runtime.suspend_count,
                      g_a_usb_diag_runtime.cmsis_rx_count,
                      g_a_usb_diag_runtime.cmsis_tx_count,
                      g_a_usb_diag_runtime.fido_rx_count,
                      g_a_usb_diag_runtime.fido_tx_count,
                      g_a_usb_diag_runtime.fido_last_req_word0,
                      g_a_usb_diag_runtime.fido_last_rsp_word0,
                      g_a_usb_diag_runtime.fido_last_status,
                      fido_ui.ui_state,
                      fido_ui.pending_cmd,
                      flash_info.present,
                      flash_info.jedec_id,
                      flash_info.capacity_bytes,
                      flash_info.spi_mode,
                      aux_status.enc_a,
                      aux_status.enc_b,
                      aux_status.enc_btn,
                      aux_status.encoder_position,
                      aux_status.last_events);
    if ((now - last_log_ms) >= 1000U)
    {
      last_log_ms = now;
      printf("AUSB R=%lu S=%lu O=%lu I=%lu U=%lu C=%lu D=%lu IRQ=%lu AS=%lu OS=%lu LEP=%lu LFS=%lu DS=%u CFG=%lu\r\n",
             g_a_usb_diag_runtime.reset_count,
             g_a_usb_diag_runtime.setup_count,
             g_a_usb_diag_runtime.data_out_count,
             g_a_usb_diag_runtime.data_in_count,
             g_a_usb_diag_runtime.suspend_count,
             g_a_usb_diag_runtime.connect_count,
             g_a_usb_diag_runtime.disconnect_count,
             g_a_usb_diag_runtime.irq_count,
             g_a_usb_diag_runtime.activate_setup_count,
             g_a_usb_diag_runtime.ep0_out_start_count,
             g_a_usb_diag_runtime.open_ep_count,
             g_a_usb_diag_runtime.open_ep_fail_count,
             hUsbDeviceHS.dev_state,
             hUsbDeviceHS.dev_config);
      printf("AHID C=%lu CLS=%lu BM=%02lX BR=%02lX WV=%04lX WI=%04lX WL=%04lX RL=%lu\r\n",
             g_a_usb_diag_runtime.hid_setup_count,
             g_a_usb_diag_runtime.hid_last_class,
             g_a_usb_diag_runtime.hid_last_bmRequest & 0xFFu,
             g_a_usb_diag_runtime.hid_last_bRequest & 0xFFu,
             g_a_usb_diag_runtime.hid_last_wValue & 0xFFFFu,
             g_a_usb_diag_runtime.hid_last_wIndex & 0xFFFFu,
             g_a_usb_diag_runtime.hid_last_wLength & 0xFFFFu,
             g_a_usb_diag_runtime.hid_last_report_len);
      printf("AIF C=%lu IDX=%lu CLS=%lu BM=%02lX BR=%02lX ST=%lu\r\n",
             g_a_usb_diag_runtime.itf_req_count,
             g_a_usb_diag_runtime.itf_last_index,
             g_a_usb_diag_runtime.itf_last_class,
             g_a_usb_diag_runtime.itf_last_bmRequest & 0xFFu,
             g_a_usb_diag_runtime.itf_last_bRequest & 0xFFu,
             g_a_usb_diag_runtime.itf_last_status);
      printf("AFID RX=%lu TX=%lu RL=%lu TL=%lu RW0=%08lX RW1=%08lX TW0=%08lX TW1=%08lX ST=%lu\r\n",
             g_a_usb_diag_runtime.fido_rx_count,
             g_a_usb_diag_runtime.fido_tx_count,
             g_a_usb_diag_runtime.fido_last_req_len,
             g_a_usb_diag_runtime.fido_last_rsp_len,
             g_a_usb_diag_runtime.fido_last_req_word0,
             g_a_usb_diag_runtime.fido_last_req_word1,
             g_a_usb_diag_runtime.fido_last_rsp_word0,
             g_a_usb_diag_runtime.fido_last_rsp_word1,
             g_a_usb_diag_runtime.fido_last_status);
    }

    lcd_status_tick(now);

   
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.LSEState = RCC_LSE_OFF;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 8;
  RCC_OscInitStruct.PLL.PLLN = 168;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK)
  {
    Error_Handler();
  }
}

/* USER CODE BEGIN 4 */
/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  puts("Error_Handler");
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
