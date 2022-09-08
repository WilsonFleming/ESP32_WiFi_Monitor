#ifndef SNIFFER_H_
#define SNIFFER_H_

#include <esp_log.h>
#include <esp_netif.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <string.h>
#include <sdmmc_cmd.h>
#include <esp_vfs_fat.h>
#include <driver/sdspi_host.h>
#include <hal/spi_types.h>

#define MANAGEMENT 0x00
#define CONTROL 0x04
#define DATA 0x08

#define ASSOCIATION_REQUEST 0x00
#define REASSOCIATION_REQUEST 0x02
#define PROBE_REQUEST 0x04
#define TIMING_ADVERTISMENT 0x06
#define BEACON 0x08
#define DISASSOCIATION 0x0A
#define DEAUTHENTICATION 0x0C
#define AUTHENTICATION 0x0B
#define ACTION 0x0E
#define ASSOCIATION_RESPONSE 0x01
#define REASSOCIATION_RESPONSE 0x03
#define PROBE_RESPONSE 0x05

// Future SD Card SPI Defines
#define MOUNT_POINT "/sdcard"
#define MOSI 23
#define MISO 19
#define CLK 18
#define CS 5

#define EXTRACT_PACKET

extern QueueHandle_t packet_queue;
extern TaskHandle_t xHandle_write;
extern TaskHandle_t xHandle_sniff;
extern TaskHandle_t xHandle_hop;

typedef struct station_t {
    char bssid[6];
    char essid[33];
    uint8_t last_rssi;
    uint64_t last_timestamp;
} station_t;

typedef struct client_t {
    char mac[6];
    uint8_t last_rssi;
    uint64_t last_timestamp;
} client_t;

extern uint8_t _current_stations;
extern uint8_t _current_clients;

extern client_t clients[255];
extern station_t stations[255];

void sniffer_init();
void sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);
void sniffer_deinit();
void handle_packet_task(void *pvParameter);
void sniffer_task(void *pvParameter);
void hopping_task(void *pvParameter);
void handle_beacon(void *buf);
bool check_station_exists(char* bssid);
void add_station(wifi_promiscuous_pkt_t *packet);

#endif // SNIFFER_H_