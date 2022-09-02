#ifndef SNIFFER_H_
#define SNIFFER_H_

#include <esp_log.h>
#include <esp_netif.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>

extern QueueHandle_t packet_queue;
extern TaskHandle_t xHandle_write;
extern TaskHandle_t xHandle_sniff;
extern TaskHandle_t xHandle_hop;

void sniffer_init();
void sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);
void sniffer_deinit();
void write_packet_task(void *pvParameter);
void sniffer_task(void *pvParameter);
void hopping_task(void *pvParameter);

#endif // SNIFFER_H_