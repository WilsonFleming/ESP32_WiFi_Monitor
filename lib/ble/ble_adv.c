#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ble_common.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_bt.h"

#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"

#define RGB_DEVICE_NAME     "ESP32 RGB"

#define adv_config_flag      (1 << 0)
static uint8_t adv_config_done = 0;

static esp_ble_adv_params_t adv_params = {
    .adv_int_min        = 0x20,
    .adv_int_max        = 0x40,
    .adv_type           = ADV_TYPE_IND,
    .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
    .channel_map        = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

void ble_rgb_adv_config(void)
{
    esp_ble_adv_data_t adv_data = {
        .set_scan_rsp = false,
        .include_name = true,
        .include_txpower = false,
        .min_interval = 0x0006, //slave connection min interval, Time = min_interval * 1.25 msec
        .max_interval = 0x0010, //slave connection max interval, Time = max_interval * 1.25 msec
        .appearance = 0x00,
        .manufacturer_len = 0, 
        .p_manufacturer_data =  NULL, 
        .service_data_len = 0,
        .p_service_data = NULL,
        .service_uuid_len = 0,
        .p_service_uuid = NULL,
        .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
    };

    esp_err_t set_dev_name_ret = esp_ble_gap_set_device_name(RGB_DEVICE_NAME);
    if (set_dev_name_ret){
        ESP_LOGE(RGB_TAG, "set device name failed, error code = %x", set_dev_name_ret);
    }
    
    //config adv data
    esp_err_t ret = esp_ble_gap_config_adv_data(&adv_data);
    if (ret){
        ESP_LOGE(RGB_TAG, "config adv data failed, error code = %x", ret);
    }
    adv_config_done |= adv_config_flag;
}

void ble_rgb_adv_start(void)
{
    esp_ble_gap_start_advertising(&adv_params);
}

void ble_rgb_adv_set_complete_handle(void)
{
    adv_config_done &= (~adv_config_flag);
    if (adv_config_done == 0){
        esp_ble_gap_start_advertising(&adv_params);
    }
}