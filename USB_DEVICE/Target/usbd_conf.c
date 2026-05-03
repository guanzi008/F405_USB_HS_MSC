/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : Target/usbd_conf.c
  * @version        : v1.0_Cube
  * @brief          : This file implements the board support package for the USB device library
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
#include "stm32f4xx.h"
#include "stm32f4xx_hal.h"
#include "usbd_def.h"
#include "usbd_core.h"

#include "usbd_hid.h"
#include "usbd_fido_class.h"
#include "usbd_msc.h"

/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/

/* USER CODE BEGIN PV */
/* Private variables ---------------------------------------------------------*/
volatile A_USB_DiagRuntime g_a_usb_diag_runtime;

/* USER CODE END PV */

PCD_HandleTypeDef hpcd_USB_OTG_HS;
void Error_Handler(void);

/* External functions --------------------------------------------------------*/
void SystemClock_Config(void);

/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/* USER CODE BEGIN PFP */
/* Private function prototypes -----------------------------------------------*/
USBD_StatusTypeDef USBD_Get_USB_Status(HAL_StatusTypeDef hal_status);

/* USER CODE END PFP */

/* Private functions ---------------------------------------------------------*/

/* USER CODE BEGIN 1 */
void a_usb_diag_note_irq(void)
{
  g_a_usb_diag_runtime.irq_count++;
}

void a_usb_diag_note_activate_setup(void)
{
  g_a_usb_diag_runtime.activate_setup_count++;
}

void a_usb_diag_note_ep0_out_start(void)
{
  g_a_usb_diag_runtime.ep0_out_start_count++;
}

void a_usb_diag_capture_registers(void)
{
  USB_OTG_GlobalTypeDef *usb = USB_OTG_HS;
  USB_OTG_DeviceTypeDef *dev = (USB_OTG_DeviceTypeDef *)((uint32_t)usb + USB_OTG_DEVICE_BASE);
  USB_OTG_INEndpointTypeDef *inep0 =
      (USB_OTG_INEndpointTypeDef *)((uint32_t)usb + USB_OTG_IN_ENDPOINT_BASE);
  USB_OTG_OUTEndpointTypeDef *outep0 =
      (USB_OTG_OUTEndpointTypeDef *)((uint32_t)usb + USB_OTG_OUT_ENDPOINT_BASE);
  g_a_usb_diag_runtime.gintsts = usb->GINTSTS;
  g_a_usb_diag_runtime.gintmsk = usb->GINTMSK;
  g_a_usb_diag_runtime.gotgctl = usb->GOTGCTL;
  g_a_usb_diag_runtime.gotgint = usb->GOTGINT;
  g_a_usb_diag_runtime.gusbcfg = usb->GUSBCFG;
  g_a_usb_diag_runtime.gccfg = usb->GCCFG;
  g_a_usb_diag_runtime.dcfg = dev->DCFG;
  g_a_usb_diag_runtime.dsts = dev->DSTS;
  g_a_usb_diag_runtime.dctl = dev->DCTL;
  g_a_usb_diag_runtime.daint = dev->DAINT;
  g_a_usb_diag_runtime.daintmsk = dev->DAINTMSK;
  g_a_usb_diag_runtime.diepint0 = inep0->DIEPINT;
  g_a_usb_diag_runtime.doepint0 = outep0->DOEPINT;
  g_a_usb_diag_runtime.doeptsiz0 = outep0->DOEPTSIZ;
}

/* USER CODE END 1 */

/*******************************************************************************
                       LL Driver Callbacks (PCD -> USB Device Library)
*******************************************************************************/
/* MSP Init */

void HAL_PCD_MspInit(PCD_HandleTypeDef* pcdHandle)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  if(pcdHandle->Instance==USB_OTG_HS)
  {
  /* USER CODE BEGIN USB_OTG_HS_MspInit 0 */

  /* USER CODE END USB_OTG_HS_MspInit 0 */

    __HAL_RCC_GPIOC_CLK_ENABLE();
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();
    /**USB_OTG_HS GPIO Configuration
    PC0     ------> USB_OTG_HS_ULPI_STP
    PC2     ------> USB_OTG_HS_ULPI_DIR
    PC3     ------> USB_OTG_HS_ULPI_NXT
    PA3     ------> USB_OTG_HS_ULPI_D0
    PA5     ------> USB_OTG_HS_ULPI_CK
    PB0     ------> USB_OTG_HS_ULPI_D1
    PB1     ------> USB_OTG_HS_ULPI_D2
    PB10     ------> USB_OTG_HS_ULPI_D3
    PB11     ------> USB_OTG_HS_ULPI_D4
    PB12     ------> USB_OTG_HS_ULPI_D5
    PB13     ------> USB_OTG_HS_ULPI_D6
    PB5     ------> USB_OTG_HS_ULPI_D7
    */
    GPIO_InitStruct.Pin = GPIO_PIN_0|GPIO_PIN_2|GPIO_PIN_3;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF10_OTG_HS;
    HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = GPIO_PIN_3|GPIO_PIN_5;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF10_OTG_HS;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = GPIO_PIN_0|GPIO_PIN_1|GPIO_PIN_10|GPIO_PIN_11
                          |GPIO_PIN_12|GPIO_PIN_13|GPIO_PIN_5;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF10_OTG_HS;
    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

    /* Peripheral clock enable */
    __HAL_RCC_USB_OTG_HS_CLK_ENABLE();
    __HAL_RCC_USB_OTG_HS_ULPI_CLK_ENABLE();

    /* Peripheral interrupt init */
    HAL_NVIC_SetPriority(OTG_HS_IRQn, 6, 0);
    HAL_NVIC_EnableIRQ(OTG_HS_IRQn);
  /* USER CODE BEGIN USB_OTG_HS_MspInit 1 */

  /* USER CODE END USB_OTG_HS_MspInit 1 */
  }
}

void HAL_PCD_MspDeInit(PCD_HandleTypeDef* pcdHandle)
{
  if(pcdHandle->Instance==USB_OTG_HS)
  {
  /* USER CODE BEGIN USB_OTG_HS_MspDeInit 0 */

  /* USER CODE END USB_OTG_HS_MspDeInit 0 */
    /* Disable Peripheral clock */
    __HAL_RCC_USB_OTG_HS_CLK_DISABLE();
    __HAL_RCC_USB_OTG_HS_ULPI_CLK_DISABLE();

    /**USB_OTG_HS GPIO Configuration
    PC0     ------> USB_OTG_HS_ULPI_STP
    PC2     ------> USB_OTG_HS_ULPI_DIR
    PC3     ------> USB_OTG_HS_ULPI_NXT
    PA3     ------> USB_OTG_HS_ULPI_D0
    PA5     ------> USB_OTG_HS_ULPI_CK
    PB0     ------> USB_OTG_HS_ULPI_D1
    PB1     ------> USB_OTG_HS_ULPI_D2
    PB10     ------> USB_OTG_HS_ULPI_D3
    PB11     ------> USB_OTG_HS_ULPI_D4
    PB12     ------> USB_OTG_HS_ULPI_D5
    PB13     ------> USB_OTG_HS_ULPI_D6
    PB5     ------> USB_OTG_HS_ULPI_D7
    */
    HAL_GPIO_DeInit(GPIOC, GPIO_PIN_0|GPIO_PIN_2|GPIO_PIN_3);

    HAL_GPIO_DeInit(GPIOA, GPIO_PIN_3|GPIO_PIN_5);

    HAL_GPIO_DeInit(GPIOB, GPIO_PIN_0|GPIO_PIN_1|GPIO_PIN_10|GPIO_PIN_11
                          |GPIO_PIN_12|GPIO_PIN_13|GPIO_PIN_5);

    /* Peripheral interrupt Deinit*/
    HAL_NVIC_DisableIRQ(OTG_HS_IRQn);

  /* USER CODE BEGIN USB_OTG_HS_MspDeInit 1 */

  /* USER CODE END USB_OTG_HS_MspDeInit 1 */
  }
}

/**
  * @brief  Setup stage callback
  * @param  hpcd: PCD handle
  * @retval None
  */
#if (USE_HAL_PCD_REGISTER_CALLBACKS == 1U)
static void PCD_SetupStageCallback(PCD_HandleTypeDef *hpcd)
#else
void HAL_PCD_SetupStageCallback(PCD_HandleTypeDef *hpcd)
#endif /* USE_HAL_PCD_REGISTER_CALLBACKS */
{
  g_a_usb_diag_runtime.setup_count++;
  g_a_usb_diag_runtime.last_setup_word0 = ((uint32_t *)hpcd->Setup)[0];
  g_a_usb_diag_runtime.last_setup_word1 = ((uint32_t *)hpcd->Setup)[1];
  USBD_LL_SetupStage((USBD_HandleTypeDef*)hpcd->pData, (uint8_t *)hpcd->Setup);
}

/**
  * @brief  Data Out stage callback.
  * @param  hpcd: PCD handle
  * @param  epnum: Endpoint number
  * @retval None
  */
#if (USE_HAL_PCD_REGISTER_CALLBACKS == 1U)
static void PCD_DataOutStageCallback(PCD_HandleTypeDef *hpcd, uint8_t epnum)
#else
void HAL_PCD_DataOutStageCallback(PCD_HandleTypeDef *hpcd, uint8_t epnum)
#endif /* USE_HAL_PCD_REGISTER_CALLBACKS */
{
  g_a_usb_diag_runtime.data_out_count++;
  USBD_LL_DataOutStage((USBD_HandleTypeDef*)hpcd->pData, epnum, hpcd->OUT_ep[epnum].xfer_buff);
}

/**
  * @brief  Data In stage callback.
  * @param  hpcd: PCD handle
  * @param  epnum: Endpoint number
  * @retval None
  */
#if (USE_HAL_PCD_REGISTER_CALLBACKS == 1U)
static void PCD_DataInStageCallback(PCD_HandleTypeDef *hpcd, uint8_t epnum)
#else
void HAL_PCD_DataInStageCallback(PCD_HandleTypeDef *hpcd, uint8_t epnum)
#endif /* USE_HAL_PCD_REGISTER_CALLBACKS */
{
  g_a_usb_diag_runtime.data_in_count++;
  USBD_LL_DataInStage((USBD_HandleTypeDef*)hpcd->pData, epnum, hpcd->IN_ep[epnum].xfer_buff);
}

/**
  * @brief  SOF callback.
  * @param  hpcd: PCD handle
  * @retval None
  */
#if (USE_HAL_PCD_REGISTER_CALLBACKS == 1U)
static void PCD_SOFCallback(PCD_HandleTypeDef *hpcd)
#else
void HAL_PCD_SOFCallback(PCD_HandleTypeDef *hpcd)
#endif /* USE_HAL_PCD_REGISTER_CALLBACKS */
{
  USBD_LL_SOF((USBD_HandleTypeDef*)hpcd->pData);
}

/**
  * @brief  Reset callback.
  * @param  hpcd: PCD handle
  * @retval None
  */
#if (USE_HAL_PCD_REGISTER_CALLBACKS == 1U)
static void PCD_ResetCallback(PCD_HandleTypeDef *hpcd)
#else
void HAL_PCD_ResetCallback(PCD_HandleTypeDef *hpcd)
#endif /* USE_HAL_PCD_REGISTER_CALLBACKS */
{
  g_a_usb_diag_runtime.reset_count++;
  USBD_SpeedTypeDef speed = USBD_SPEED_FULL;

  if ( hpcd->Init.speed == PCD_SPEED_HIGH)
  {
    speed = USBD_SPEED_HIGH;
  }
  else if ( hpcd->Init.speed == PCD_SPEED_FULL)
  {
    speed = USBD_SPEED_FULL;
  }
  else
  {
    Error_Handler();
  }
    /* Set Speed. */
  USBD_LL_SetSpeed((USBD_HandleTypeDef*)hpcd->pData, speed);

  /* Reset Device. */
  USBD_LL_Reset((USBD_HandleTypeDef*)hpcd->pData);
}

/**
  * @brief  Suspend callback.
  * When Low power mode is enabled the debug cannot be used (IAR, Keil doesn't support it)
  * @param  hpcd: PCD handle
  * @retval None
  */
#if (USE_HAL_PCD_REGISTER_CALLBACKS == 1U)
static void PCD_SuspendCallback(PCD_HandleTypeDef *hpcd)
#else
void HAL_PCD_SuspendCallback(PCD_HandleTypeDef *hpcd)
#endif /* USE_HAL_PCD_REGISTER_CALLBACKS */
{
  g_a_usb_diag_runtime.suspend_count++;
  /* Inform USB library that core enters in suspend Mode. */
  USBD_LL_Suspend((USBD_HandleTypeDef*)hpcd->pData);
  __HAL_PCD_GATE_PHYCLOCK(hpcd);
  /* Enter in STOP mode. */
  /* USER CODE BEGIN 2 */
  if (hpcd->Init.low_power_enable)
  {
    /* Set SLEEPDEEP bit and SleepOnExit of Cortex System Control Register. */
    SCB->SCR |= (uint32_t)((uint32_t)(SCB_SCR_SLEEPDEEP_Msk | SCB_SCR_SLEEPONEXIT_Msk));
  }
  /* USER CODE END 2 */
}

/**
  * @brief  Resume callback.
  * When Low power mode is enabled the debug cannot be used (IAR, Keil doesn't support it)
  * @param  hpcd: PCD handle
  * @retval None
  */
#if (USE_HAL_PCD_REGISTER_CALLBACKS == 1U)
static void PCD_ResumeCallback(PCD_HandleTypeDef *hpcd)
#else
void HAL_PCD_ResumeCallback(PCD_HandleTypeDef *hpcd)
#endif /* USE_HAL_PCD_REGISTER_CALLBACKS */
{
  g_a_usb_diag_runtime.resume_count++;
  /* USER CODE BEGIN 3 */

  /* USER CODE END 3 */
  USBD_LL_Resume((USBD_HandleTypeDef*)hpcd->pData);
}

/**
  * @brief  ISOOUTIncomplete callback.
  * @param  hpcd: PCD handle
  * @param  epnum: Endpoint number
  * @retval None
  */
#if (USE_HAL_PCD_REGISTER_CALLBACKS == 1U)
static void PCD_ISOOUTIncompleteCallback(PCD_HandleTypeDef *hpcd, uint8_t epnum)
#else
void HAL_PCD_ISOOUTIncompleteCallback(PCD_HandleTypeDef *hpcd, uint8_t epnum)
#endif /* USE_HAL_PCD_REGISTER_CALLBACKS */
{
  USBD_LL_IsoOUTIncomplete((USBD_HandleTypeDef*)hpcd->pData, epnum);
}

/**
  * @brief  ISOINIncomplete callback.
  * @param  hpcd: PCD handle
  * @param  epnum: Endpoint number
  * @retval None
  */
#if (USE_HAL_PCD_REGISTER_CALLBACKS == 1U)
static void PCD_ISOINIncompleteCallback(PCD_HandleTypeDef *hpcd, uint8_t epnum)
#else
void HAL_PCD_ISOINIncompleteCallback(PCD_HandleTypeDef *hpcd, uint8_t epnum)
#endif /* USE_HAL_PCD_REGISTER_CALLBACKS */
{
  USBD_LL_IsoINIncomplete((USBD_HandleTypeDef*)hpcd->pData, epnum);
}

/**
  * @brief  Connect callback.
  * @param  hpcd: PCD handle
  * @retval None
  */
#if (USE_HAL_PCD_REGISTER_CALLBACKS == 1U)
static void PCD_ConnectCallback(PCD_HandleTypeDef *hpcd)
#else
void HAL_PCD_ConnectCallback(PCD_HandleTypeDef *hpcd)
#endif /* USE_HAL_PCD_REGISTER_CALLBACKS */
{
  g_a_usb_diag_runtime.connect_count++;
  USBD_LL_DevConnected((USBD_HandleTypeDef*)hpcd->pData);
}

/**
  * @brief  Disconnect callback.
  * @param  hpcd: PCD handle
  * @retval None
  */
#if (USE_HAL_PCD_REGISTER_CALLBACKS == 1U)
static void PCD_DisconnectCallback(PCD_HandleTypeDef *hpcd)
#else
void HAL_PCD_DisconnectCallback(PCD_HandleTypeDef *hpcd)
#endif /* USE_HAL_PCD_REGISTER_CALLBACKS */
{
  g_a_usb_diag_runtime.disconnect_count++;
  USBD_LL_DevDisconnected((USBD_HandleTypeDef*)hpcd->pData);
}

/*******************************************************************************
                       LL Driver Interface (USB Device Library --> PCD)
*******************************************************************************/

/**
  * @brief  Initializes the low level portion of the device driver.
  * @param  pdev: Device handle
  * @retval USBD status
  */
USBD_StatusTypeDef USBD_LL_Init(USBD_HandleTypeDef *pdev)
{
  /* Init USB Ip. */
  if (pdev->id == DEVICE_HS) {
  /* Link the driver to the stack. */
  hpcd_USB_OTG_HS.pData = pdev;
  pdev->pData = &hpcd_USB_OTG_HS;

  hpcd_USB_OTG_HS.Instance = USB_OTG_HS;
  hpcd_USB_OTG_HS.Init.dev_endpoints = 6;
  hpcd_USB_OTG_HS.Init.speed = PCD_SPEED_HIGH;
  hpcd_USB_OTG_HS.Init.dma_enable = ENABLE;
  hpcd_USB_OTG_HS.Init.phy_itface = USB_OTG_ULPI_PHY;
  hpcd_USB_OTG_HS.Init.Sof_enable = DISABLE;
  hpcd_USB_OTG_HS.Init.low_power_enable = DISABLE;
  hpcd_USB_OTG_HS.Init.lpm_enable = DISABLE;
  hpcd_USB_OTG_HS.Init.vbus_sensing_enable = DISABLE;
  hpcd_USB_OTG_HS.Init.use_dedicated_ep1 = DISABLE;
  hpcd_USB_OTG_HS.Init.use_external_vbus = DISABLE;
  if (HAL_PCD_Init(&hpcd_USB_OTG_HS) != HAL_OK)
  {
    Error_Handler( );
  }

#if (USE_HAL_PCD_REGISTER_CALLBACKS == 1U)
  /* Register USB PCD CallBacks */
  HAL_PCD_RegisterCallback(&hpcd_USB_OTG_HS, HAL_PCD_SOF_CB_ID, PCD_SOFCallback);
  HAL_PCD_RegisterCallback(&hpcd_USB_OTG_HS, HAL_PCD_SETUPSTAGE_CB_ID, PCD_SetupStageCallback);
  HAL_PCD_RegisterCallback(&hpcd_USB_OTG_HS, HAL_PCD_RESET_CB_ID, PCD_ResetCallback);
  HAL_PCD_RegisterCallback(&hpcd_USB_OTG_HS, HAL_PCD_SUSPEND_CB_ID, PCD_SuspendCallback);
  HAL_PCD_RegisterCallback(&hpcd_USB_OTG_HS, HAL_PCD_RESUME_CB_ID, PCD_ResumeCallback);
  HAL_PCD_RegisterCallback(&hpcd_USB_OTG_HS, HAL_PCD_CONNECT_CB_ID, PCD_ConnectCallback);
  HAL_PCD_RegisterCallback(&hpcd_USB_OTG_HS, HAL_PCD_DISCONNECT_CB_ID, PCD_DisconnectCallback);

  HAL_PCD_RegisterDataOutStageCallback(&hpcd_USB_OTG_HS, PCD_DataOutStageCallback);
  HAL_PCD_RegisterDataInStageCallback(&hpcd_USB_OTG_HS, PCD_DataInStageCallback);
  HAL_PCD_RegisterIsoOutIncpltCallback(&hpcd_USB_OTG_HS, PCD_ISOOUTIncompleteCallback);
  HAL_PCD_RegisterIsoInIncpltCallback(&hpcd_USB_OTG_HS, PCD_ISOINIncompleteCallback);
#endif /* USE_HAL_PCD_REGISTER_CALLBACKS */
  /*
   * Composite layout:
   *   EP0 IN  = control
   *   EP1 IN  = CMSIS-DAP HID interrupt
   *   EP2 IN  = MSC bulk
   *   EP3 IN  = FIDO HID interrupt
   *   EP4 IN  = UART keyboard HID interrupt
   *   EP5 IN  = UART mouse HID interrupt
   *
   * Each active IN endpoint needs a dedicated Tx FIFO. Missing FIFOs for the
   * keyboard/mouse endpoints make Linux enumerate the interface descriptor and
   * then time out while probing usbhid.
   */
  HAL_PCDEx_SetRxFiFo(&hpcd_USB_OTG_HS, 0x200);
  HAL_PCDEx_SetTxFiFo(&hpcd_USB_OTG_HS, 0, 0x40);
  HAL_PCDEx_SetTxFiFo(&hpcd_USB_OTG_HS, 1, 0x40);
  HAL_PCDEx_SetTxFiFo(&hpcd_USB_OTG_HS, 2, 0x80);
  HAL_PCDEx_SetTxFiFo(&hpcd_USB_OTG_HS, 3, 0x40);
  HAL_PCDEx_SetTxFiFo(&hpcd_USB_OTG_HS, 4, 0x20);
  HAL_PCDEx_SetTxFiFo(&hpcd_USB_OTG_HS, 5, 0x20);
  }
  return USBD_OK;
}

/**
  * @brief  De-Initializes the low level portion of the device driver.
  * @param  pdev: Device handle
  * @retval USBD status
  */
USBD_StatusTypeDef USBD_LL_DeInit(USBD_HandleTypeDef *pdev)
{
  HAL_StatusTypeDef hal_status = HAL_OK;
  USBD_StatusTypeDef usb_status = USBD_OK;

  hal_status = HAL_PCD_DeInit(pdev->pData);

  usb_status =  USBD_Get_USB_Status(hal_status);

  return usb_status;
}

/**
  * @brief  Starts the low level portion of the device driver.
  * @param  pdev: Device handle
  * @retval USBD status
  */
USBD_StatusTypeDef USBD_LL_Start(USBD_HandleTypeDef *pdev)
{
  HAL_StatusTypeDef hal_status = HAL_OK;
  USBD_StatusTypeDef usb_status = USBD_OK;

  hal_status = HAL_PCD_Start(pdev->pData);

  usb_status =  USBD_Get_USB_Status(hal_status);

  return usb_status;
}

/**
  * @brief  Stops the low level portion of the device driver.
  * @param  pdev: Device handle
  * @retval USBD status
  */
USBD_StatusTypeDef USBD_LL_Stop(USBD_HandleTypeDef *pdev)
{
  HAL_StatusTypeDef hal_status = HAL_OK;
  USBD_StatusTypeDef usb_status = USBD_OK;

  hal_status = HAL_PCD_Stop(pdev->pData);

  usb_status =  USBD_Get_USB_Status(hal_status);

  return usb_status;
}

/**
  * @brief  Opens an endpoint of the low level driver.
  * @param  pdev: Device handle
  * @param  ep_addr: Endpoint number
  * @param  ep_type: Endpoint type
  * @param  ep_mps: Endpoint max packet size
  * @retval USBD status
  */
USBD_StatusTypeDef USBD_LL_OpenEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr, uint8_t ep_type, uint16_t ep_mps)
{
  HAL_StatusTypeDef hal_status = HAL_OK;
  USBD_StatusTypeDef usb_status = USBD_OK;

  g_a_usb_diag_runtime.open_ep_count++;
  g_a_usb_diag_runtime.last_open_ep_addr = ep_addr;
  g_a_usb_diag_runtime.last_open_ep_type = ep_type;
  g_a_usb_diag_runtime.last_open_ep_mps = ep_mps;
  hal_status = HAL_PCD_EP_Open(pdev->pData, ep_addr, ep_mps, ep_type);
  g_a_usb_diag_runtime.last_open_ep_status = (uint32_t)hal_status;

  usb_status =  USBD_Get_USB_Status(hal_status);
  if (usb_status != USBD_OK)
  {
    g_a_usb_diag_runtime.open_ep_fail_count++;
  }

  return usb_status;
}

/**
  * @brief  Closes an endpoint of the low level driver.
  * @param  pdev: Device handle
  * @param  ep_addr: Endpoint number
  * @retval USBD status
  */
USBD_StatusTypeDef USBD_LL_CloseEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr)
{
  HAL_StatusTypeDef hal_status = HAL_OK;
  USBD_StatusTypeDef usb_status = USBD_OK;

  hal_status = HAL_PCD_EP_Close(pdev->pData, ep_addr);

  usb_status =  USBD_Get_USB_Status(hal_status);

  return usb_status;
}

/**
  * @brief  Flushes an endpoint of the Low Level Driver.
  * @param  pdev: Device handle
  * @param  ep_addr: Endpoint number
  * @retval USBD status
  */
USBD_StatusTypeDef USBD_LL_FlushEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr)
{
  HAL_StatusTypeDef hal_status = HAL_OK;
  USBD_StatusTypeDef usb_status = USBD_OK;

  hal_status = HAL_PCD_EP_Flush(pdev->pData, ep_addr);

  usb_status =  USBD_Get_USB_Status(hal_status);

  return usb_status;
}

/**
  * @brief  Sets a Stall condition on an endpoint of the Low Level Driver.
  * @param  pdev: Device handle
  * @param  ep_addr: Endpoint number
  * @retval USBD status
  */
USBD_StatusTypeDef USBD_LL_StallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr)
{
  HAL_StatusTypeDef hal_status = HAL_OK;
  USBD_StatusTypeDef usb_status = USBD_OK;

  hal_status = HAL_PCD_EP_SetStall(pdev->pData, ep_addr);

  usb_status =  USBD_Get_USB_Status(hal_status);

  return usb_status;
}

/**
  * @brief  Clears a Stall condition on an endpoint of the Low Level Driver.
  * @param  pdev: Device handle
  * @param  ep_addr: Endpoint number
  * @retval USBD status
  */
USBD_StatusTypeDef USBD_LL_ClearStallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr)
{
  HAL_StatusTypeDef hal_status = HAL_OK;
  USBD_StatusTypeDef usb_status = USBD_OK;

  hal_status = HAL_PCD_EP_ClrStall(pdev->pData, ep_addr);

  usb_status =  USBD_Get_USB_Status(hal_status);

  return usb_status;
}

/**
  * @brief  Returns Stall condition.
  * @param  pdev: Device handle
  * @param  ep_addr: Endpoint number
  * @retval Stall (1: Yes, 0: No)
  */
uint8_t USBD_LL_IsStallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr)
{
  PCD_HandleTypeDef *hpcd = (PCD_HandleTypeDef*) pdev->pData;

  if((ep_addr & 0x80) == 0x80)
  {
    return hpcd->IN_ep[ep_addr & 0x7F].is_stall;
  }
  else
  {
    return hpcd->OUT_ep[ep_addr & 0x7F].is_stall;
  }
}

/**
  * @brief  Assigns a USB address to the device.
  * @param  pdev: Device handle
  * @param  dev_addr: Device address
  * @retval USBD status
  */
USBD_StatusTypeDef USBD_LL_SetUSBAddress(USBD_HandleTypeDef *pdev, uint8_t dev_addr)
{
  HAL_StatusTypeDef hal_status = HAL_OK;
  USBD_StatusTypeDef usb_status = USBD_OK;

  hal_status = HAL_PCD_SetAddress(pdev->pData, dev_addr);

  usb_status =  USBD_Get_USB_Status(hal_status);

  return usb_status;
}

/**
  * @brief  Transmits data over an endpoint.
  * @param  pdev: Device handle
  * @param  ep_addr: Endpoint number
  * @param  pbuf: Pointer to data to be sent
  * @param  size: Data size
  * @retval USBD status
  */
USBD_StatusTypeDef USBD_LL_Transmit(USBD_HandleTypeDef *pdev, uint8_t ep_addr, uint8_t *pbuf, uint32_t size)
{
  HAL_StatusTypeDef hal_status = HAL_OK;
  USBD_StatusTypeDef usb_status = USBD_OK;

  hal_status = HAL_PCD_EP_Transmit(pdev->pData, ep_addr, pbuf, size);

  usb_status =  USBD_Get_USB_Status(hal_status);

  return usb_status;
}

/**
  * @brief  Prepares an endpoint for reception.
  * @param  pdev: Device handle
  * @param  ep_addr: Endpoint number
  * @param  pbuf: Pointer to data to be received
  * @param  size: Data size
  * @retval USBD status
  */
USBD_StatusTypeDef USBD_LL_PrepareReceive(USBD_HandleTypeDef *pdev, uint8_t ep_addr, uint8_t *pbuf, uint32_t size)
{
  HAL_StatusTypeDef hal_status = HAL_OK;
  USBD_StatusTypeDef usb_status = USBD_OK;

  hal_status = HAL_PCD_EP_Receive(pdev->pData, ep_addr, pbuf, size);

  usb_status =  USBD_Get_USB_Status(hal_status);

  return usb_status;
}

/**
  * @brief  Returns the last transferred packet size.
  * @param  pdev: Device handle
  * @param  ep_addr: Endpoint number
  * @retval Received Data Size
  */
uint32_t USBD_LL_GetRxDataSize(USBD_HandleTypeDef *pdev, uint8_t ep_addr)
{
  return HAL_PCD_EP_GetRxCount((PCD_HandleTypeDef*) pdev->pData, ep_addr);
}

#ifdef USBD_HS_TESTMODE_ENABLE
/**
  * @brief  Set High speed Test mode.
  * @param  pdev: Device handle
  * @param  testmode: test mode
  * @retval USBD Status
  */
USBD_StatusTypeDef USBD_LL_SetTestMode(USBD_HandleTypeDef *pdev, uint8_t testmode)
{
  UNUSED(pdev);
  UNUSED(testmode);

  return USBD_OK;
}
#endif /* USBD_HS_TESTMODE_ENABLE */

/**
  * @brief  Static single allocation.
  * @param  size: Size of allocated memory
  * @retval None
  */
static uint32_t s_hid_class_mem[2][(sizeof(USBD_HID_HandleTypeDef) + 3U) / 4U];
static uint32_t s_fido_class_mem[(sizeof(USBD_FIDO_HandleTypeDef) + 3U) / 4U];
static uint32_t s_msc_class_mem[(sizeof(USBD_MSC_BOT_HandleTypeDef) + 3U) / 4U];
static uint8_t s_hid_class_mem_used[2] = {0U, 0U};
static uint8_t s_fido_class_mem_used = 0U;
static uint8_t s_msc_class_mem_used = 0U;
static uint32_t s_usbd_fallback_mem[256];
static uint32_t s_usbd_fallback_offset = 0U;
static uint32_t s_usbd_fallback_alloc_count = 0U;

void *USBD_static_malloc(uint32_t size)
{
  uint32_t words = (size + 3U) / 4U;
  uint32_t start = 0U;
  uint32_t limit = 0U;
  void *ptr = NULL;

  g_a_usb_diag_runtime.malloc_call_count++;
  g_a_usb_diag_runtime.malloc_last_size = size;
  g_a_usb_diag_runtime.malloc_last_words = words;
  g_a_usb_diag_runtime.malloc_last_start = 0U;
  g_a_usb_diag_runtime.malloc_last_limit = 0U;

  if (size == sizeof(USBD_HID_HandleTypeDef))
  {
    uint32_t idx;

    limit = (uint32_t)(sizeof(s_hid_class_mem[0]) / sizeof(s_hid_class_mem[0][0]));
    for (idx = 0U; idx < 2U; ++idx)
    {
      if (s_hid_class_mem_used[idx] == 0U)
      {
        s_hid_class_mem_used[idx] = 1U;
        ptr = &s_hid_class_mem[idx][0];
        start = idx * limit;
        break;
      }
    }
  }
  else if (size == sizeof(USBD_FIDO_HandleTypeDef))
  {
    limit = (uint32_t)(sizeof(s_fido_class_mem) / sizeof(s_fido_class_mem[0]));
    if (s_fido_class_mem_used == 0U)
    {
      s_fido_class_mem_used = 1U;
      ptr = &s_fido_class_mem[0];
      start = 0U;
    }
  }
  else if (size == sizeof(USBD_MSC_BOT_HandleTypeDef))
  {
    limit = (uint32_t)(sizeof(s_msc_class_mem) / sizeof(s_msc_class_mem[0]));
    if (s_msc_class_mem_used == 0U)
    {
      s_msc_class_mem_used = 1U;
      ptr = &s_msc_class_mem[0];
      start = 0U;
    }
  }
  else
  {
    start = s_usbd_fallback_offset;
    limit = (uint32_t)(sizeof(s_usbd_fallback_mem) / sizeof(s_usbd_fallback_mem[0]));
    if ((start + words) <= limit)
    {
      s_usbd_fallback_offset += words;
      s_usbd_fallback_alloc_count++;
      ptr = &s_usbd_fallback_mem[start];
    }
  }

  g_a_usb_diag_runtime.malloc_last_start = start;
  g_a_usb_diag_runtime.malloc_last_limit = limit;

  if (ptr == NULL)
  {
    g_a_usb_diag_runtime.malloc_fail_count++;
    g_a_usb_diag_runtime.malloc_last_ptr = 0U;
    g_a_usb_diag_runtime.malloc_last_offset = s_usbd_fallback_offset;
    g_a_usb_diag_runtime.malloc_alloc_count =
        (uint32_t)s_hid_class_mem_used[0] +
        (uint32_t)s_hid_class_mem_used[1] +
        (uint32_t)s_fido_class_mem_used +
        (uint32_t)s_msc_class_mem_used +
        s_usbd_fallback_alloc_count;
    return NULL;
  }

  g_a_usb_diag_runtime.malloc_last_ptr = (uint32_t)(uintptr_t)ptr;
  g_a_usb_diag_runtime.malloc_last_offset = s_usbd_fallback_offset;
  g_a_usb_diag_runtime.malloc_alloc_count =
      (uint32_t)s_hid_class_mem_used[0] +
      (uint32_t)s_hid_class_mem_used[1] +
      (uint32_t)s_fido_class_mem_used +
      (uint32_t)s_msc_class_mem_used +
      s_usbd_fallback_alloc_count;
  return ptr;
}

/**
  * @brief  Dummy memory free
  * @param  p: Pointer to allocated  memory address
  * @retval None
  */
void USBD_static_free(void *p)
{
  uintptr_t addr = (uintptr_t)p;
  uintptr_t hid0_base = (uintptr_t)&s_hid_class_mem[0][0];
  uintptr_t hid0_end = (uintptr_t)(&s_hid_class_mem[0][0] + (sizeof(s_hid_class_mem[0]) / sizeof(s_hid_class_mem[0][0])));
  uintptr_t hid1_base = (uintptr_t)&s_hid_class_mem[1][0];
  uintptr_t hid1_end = (uintptr_t)(&s_hid_class_mem[1][0] + (sizeof(s_hid_class_mem[1]) / sizeof(s_hid_class_mem[1][0])));
  uintptr_t fido_base = (uintptr_t)&s_fido_class_mem[0];
  uintptr_t fido_end = (uintptr_t)(&s_fido_class_mem[0] + (sizeof(s_fido_class_mem) / sizeof(s_fido_class_mem[0])));
  uintptr_t msc_base = (uintptr_t)&s_msc_class_mem[0];
  uintptr_t msc_end = (uintptr_t)(&s_msc_class_mem[0] + (sizeof(s_msc_class_mem) / sizeof(s_msc_class_mem[0])));
  uintptr_t fallback_base = (uintptr_t)&s_usbd_fallback_mem[0];
  uintptr_t fallback_end =
      (uintptr_t)(&s_usbd_fallback_mem[0] + (sizeof(s_usbd_fallback_mem) / sizeof(s_usbd_fallback_mem[0])));

  if (p == NULL)
  {
    return;
  }

  if ((addr >= hid0_base) && (addr < hid0_end))
  {
    s_hid_class_mem_used[0] = 0U;
  }
  else if ((addr >= hid1_base) && (addr < hid1_end))
  {
    s_hid_class_mem_used[1] = 0U;
  }
  else if ((addr >= fido_base) && (addr < fido_end))
  {
    s_fido_class_mem_used = 0U;
  }
  else if ((addr >= msc_base) && (addr < msc_end))
  {
    s_msc_class_mem_used = 0U;
  }
  else if ((addr >= fallback_base) && (addr < fallback_end))
  {
    if (s_usbd_fallback_alloc_count != 0U)
    {
      s_usbd_fallback_alloc_count--;
    }
    if (s_usbd_fallback_alloc_count == 0U)
    {
      s_usbd_fallback_offset = 0U;
    }
  }
  else
  {
    return;
  }

  g_a_usb_diag_runtime.malloc_last_offset = s_usbd_fallback_offset;
  g_a_usb_diag_runtime.malloc_alloc_count =
      (uint32_t)s_hid_class_mem_used[0] +
      (uint32_t)s_hid_class_mem_used[1] +
      (uint32_t)s_fido_class_mem_used +
      (uint32_t)s_msc_class_mem_used +
      s_usbd_fallback_alloc_count;
}

/**
  * @brief  Delays routine for the USB Device Library.
  * @param  Delay: Delay in ms
  * @retval None
  */
void USBD_LL_Delay(uint32_t Delay)
{
  HAL_Delay(Delay);
}

/**
  * @brief  Returns the USB status depending on the HAL status:
  * @param  hal_status: HAL status
  * @retval USB status
  */
USBD_StatusTypeDef USBD_Get_USB_Status(HAL_StatusTypeDef hal_status)
{
  USBD_StatusTypeDef usb_status = USBD_OK;

  switch (hal_status)
  {
    case HAL_OK :
      usb_status = USBD_OK;
    break;
    case HAL_ERROR :
      usb_status = USBD_FAIL;
    break;
    case HAL_BUSY :
      usb_status = USBD_BUSY;
    break;
    case HAL_TIMEOUT :
      usb_status = USBD_FAIL;
    break;
    default :
      usb_status = USBD_FAIL;
    break;
  }
  return usb_status;
}
