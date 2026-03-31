cmake_minimum_required(VERSION 3.22)

project(stm32cubemx)
add_library(stm32cubemx INTERFACE)

# Enable CMake support for ASM and C languages
enable_language(C ASM)

target_compile_definitions(stm32cubemx INTERFACE 
	USE_HAL_DRIVER 
	STM32F405xx
    $<$<CONFIG:Debug>:DEBUG>
)

target_include_directories(stm32cubemx INTERFACE
    ../../Core/Inc
    ../../USB_DEVICE/App
    ../../USB_DEVICE/Target
    ../../USB_DEVICE/CompositeBuilder/Inc
    ../../user_code/my_public
    ../../user_code/my_device
    ../../Drivers/STM32F4xx_HAL_Driver/Inc
    ../../Drivers/STM32F4xx_HAL_Driver/Inc/Legacy
    ../../Middlewares/ST/STM32_USB_Device_Library/Core/Inc
    ../../Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Inc
    ../../Middlewares/ST/STM32_USB_Device_Library/Class/HID/Inc
    ../../Drivers/CMSIS/Device/ST/STM32F4xx/Include
    ../../Drivers/CMSIS/Include
)

target_sources(stm32cubemx INTERFACE
    ../../Core/Src/main.c
    ../../Core/Src/gpio.c
    ../../Core/Src/dma.c
    ../../Core/Src/rtc.c
    ../../Core/Src/sdio.c
    ../../Core/Src/tim.c
    ../../Core/Src/usart.c
    ../../Core/Src/aux_inputs.c
    ../../Core/Src/ext_flash_w25q.c
    ../../Core/Src/ls013_lcd.c
    ../../Core/Src/lcd_status.c
    ../../Core/Src/stm32f4xx_it.c
    ../../Core/Src/stm32f4xx_hal_msp.c
    ../../USB_DEVICE/App/usb_device.c
    ../../USB_DEVICE/App/usbd_desc.c
    ../../USB_DEVICE/App/usbd_hid_cmsisdap.c
    ../../USB_DEVICE/App/usbd_hid_fido.c
    ../../USB_DEVICE/App/usbd_ctap_min.c
    ../../USB_DEVICE/App/usbd_storage_if.c
    ../../USB_DEVICE/Target/usbd_conf.c
    ../../USB_DEVICE/CompositeBuilder/Src/usbd_composite_builder.c
    ../../user_code/my_public/my_redifine.c
    ../../user_code/my_device/led_and_key.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_pcd.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_pcd_ex.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_ll_usb.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_rcc.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_rcc_ex.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_flash.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_flash_ex.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_flash_ramfunc.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_gpio.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_dma_ex.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_dma.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_pwr.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_pwr_ex.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_cortex.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_exti.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_rtc.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_rtc_ex.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_ll_sdmmc.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_sd.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_mmc.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_tim.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_tim_ex.c
    ../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_uart.c
    ../../Core/Src/system_stm32f4xx.c
    ../../Middlewares/ST/STM32_USB_Device_Library/Core/Src/usbd_core.c
    ../../Middlewares/ST/STM32_USB_Device_Library/Core/Src/usbd_ctlreq.c
    ../../Middlewares/ST/STM32_USB_Device_Library/Core/Src/usbd_ioreq.c
    ../../Middlewares/ST/STM32_USB_Device_Library/Class/HID/Src/usbd_hid.c
    ../../Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Src/usbd_msc.c
    ../../Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Src/usbd_msc_bot.c
    ../../Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Src/usbd_msc_data.c
    ../../Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Src/usbd_msc_scsi.c
    ../../Core/Src/sysmem.c
    ../../Core/Src/syscalls.c
    ../../startup_stm32f405xx.s
)

target_link_directories(stm32cubemx INTERFACE
)

target_link_libraries(stm32cubemx INTERFACE
)

# Validate that STM32CubeMX code is compatible with C standard
if(CMAKE_C_STANDARD LESS 11)
    message(ERROR "Generated code requires C11 or higher")
endif()
