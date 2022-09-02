#include <nvs_flash.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>

#include "sniffer.h"

// static int channel = CONFIG_START_CHANNEL;

void app_main() {

    static const char * TAG = "Sniffer Main";
    
    ESP_LOGI(TAG, "[+] Starting ....... ");
    
    ESP_LOGI(TAG, "[+] Initialising NVS flash.");
    ESP_ERROR_CHECK(nvs_flash_init());

    packet_queue = xQueueCreate(CONFIG_QUEUE_SIZE, CONFIG_MAXIMUM_PKT_SIZE);

    if( packet_queue == NULL) {
        ESP_LOGE(TAG, "[!] ERROR - Packet queue creation failed.");
    }

    ESP_LOGI(TAG, "[+] Launching writing task");
    xTaskCreate(&write_packet_task, "write_task", 5000, NULL, 5, &xHandle_write);
    
    if(xHandle_write == NULL) {
        ESP_LOGE(TAG, "[!] ERROR - Write task creation failed.");
    }

    ESP_LOGI(TAG, "[+] Launching sniffing task.");
    xTaskCreate(&sniffer_task, "sniffer_task", 50000, NULL, 1, &xHandle_sniff);

    if(CONFIG_HOP) {
        ESP_LOGI(TAG, "[+] Launching channel hopping task");
    xTaskCreate(&hopping_task, "hopping_task", 5000, NULL, 5, &xHandle_hop);
    }
    
    
}