#include "sniffer.h"

QueueHandle_t packet_queue = NULL;
TaskHandle_t xHandle_write = NULL;
TaskHandle_t xHandle_sniff = NULL;
TaskHandle_t xHandle_hop = NULL;


uint8_t _current_stations = 0;
uint8_t _current_clients = 0;

client_t clients[255];
station_t stations[255];

static const char * SNIFFER_TAG = "Sniffer";

void sniffer_init() {

    ESP_ERROR_CHECK(esp_netif_init());

    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();

    ESP_ERROR_CHECK(esp_wifi_init(&config));

    const wifi_country_t wifi_country = {
        .cc = CONFIG_WIFI_COUNTRY,
        .schan = CONFIG_START_CHANNEL,
        .nchan = CONFIG_END_CHANNEL,
        .policy = WIFI_COUNTRY_POLICY_AUTO
    };

    ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country));

    // Set volatile storage of wifi data
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));

    ESP_ERROR_CHECK(esp_wifi_start());

    // Captures Management, Control and Misc packets
    const wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };

    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));

    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniffer_packet_handler));

    ESP_ERROR_CHECK(esp_wifi_set_channel(CONFIG_START_CHANNEL, WIFI_SECOND_CHAN_NONE));

    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
}

void sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
    int pkt_len;
    int pkt_rssi;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff;

    pkt_len = pkt->rx_ctrl.sig_len;
    pkt_rssi = pkt->rx_ctrl.rssi;

    if(uxQueueSpacesAvailable(packet_queue) > 0 && pkt_len < CONFIG_MAXIMUM_PKT_SIZE) {
        xQueueSendToBack(packet_queue, pkt, CONFIG_MAXIMUM_PKT_SIZE);
    
        // ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Packet Processed - Size: %d, RSSI: %d", pkt_len, pkt_rssi);
    }
}

void sniffer_deinit() {
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
    ESP_ERROR_CHECK(esp_wifi_stop());
    ESP_ERROR_CHECK(esp_wifi_deinit());
}

void handle_packet_task(void *pvParameter) {

    BaseType_t packet;
    char buff[CONFIG_MAXIMUM_PKT_SIZE];

    // TODO - Handle SD Card mounting

    while(true) {

        packet = xQueueReceive(packet_queue, &buff, 100/ portTICK_PERIOD_MS );

        if(packet == pdTRUE) {
            handle_beacon(buff);
            // TODO - Write packet to Disk
        }   
    }
}

void sniffer_task(void *pvParameter) {
    
    ESP_LOGI(SNIFFER_TAG, "[SNIFFER] - Sniffer task started.");

    ESP_LOGI(SNIFFER_TAG, "[SNIFFER] - Initialising WiFi Sniffer.");
    sniffer_init();

    ESP_LOGI(SNIFFER_TAG, "[SNIFFER] - Sniffing on channel %d", CONFIG_START_CHANNEL);

    while(true) {
        vTaskDelay( 60 * 1000 / portTICK_PERIOD_MS );
    }

}

void hopping_task(void *pvParameter) {
    
    static int channel = CONFIG_START_CHANNEL;

    vTaskDelay ( CONFIG_HOP_DWELL_TIME / portTICK_PERIOD_MS );

    while(true) {
        
        if(channel == CONFIG_END_CHANNEL - 1 ){
            channel = channel + 1;
        }
        else {
            channel = (channel + 1 ) % CONFIG_END_CHANNEL;
        }

        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

        // ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Started sniffing on channel %d", channel);

        vTaskDelay ( CONFIG_HOP_DWELL_TIME / portTICK_PERIOD_MS );
    }
}

void add_station(wifi_promiscuous_pkt_t *packet) {
    if(_current_stations == 255) {
        return;
    }
    
    station_t *station = &stations[_current_stations];
    uint8_t length;

    length = packet->payload[37];
    
    memcpy(&(station->bssid), &(packet->payload[16]), 6);

    if(length != 0) {
        memcpy(&(station->essid), &(packet->payload[38]), length);
        station->essid[length] = 0x00;
    }

    station->last_rssi = packet->rx_ctrl.rssi;

    memcpy(&(station->last_timestamp), &(packet->payload[24]), 8);

    ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Added station with BSSID %02x:%02x:%02x:%02x:%02x:%02x, SSID: %s, RSSI: %d, timestamp: %llu |", station->bssid[0], station->bssid[1], station->bssid[2], station->bssid[3], station->bssid[4], station->bssid[5], station->essid, station->last_rssi, station->last_timestamp);

    _current_stations++;
}

bool check_station_exists(char* bssid) {
    int i;

    for(i = 0; i < 256; ++i) {
        if ( memcmp(&(stations[i].bssid), bssid, 6) == 0 ) {
            return true;
        }
    }
    return false;
}

void handle_beacon(void *buf) {
    wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t*)buf;
    
    
#ifdef EXTRACT_PACKET
    bool exists;

    uint8_t type;
    uint8_t subtype;
#ifdef DEBUG
    uint8_t length;
    char essid[33];
#endif
    char bssid[6];

    // Get type
    type = packet->payload[0] & 0x0F;
    subtype = packet->payload[0] >> 4;

    switch(type) {
        case MANAGEMENT:
            switch(subtype){
                case ASSOCIATION_REQUEST:
                    // ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Association Request collected.");
                    break;
                case REASSOCIATION_REQUEST:
                    // ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Reassociation request collected.");
                    break;
                case PROBE_REQUEST:
                    // ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Probe request collected.");
                    break;
                case TIMING_ADVERTISMENT:
                    // ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Timing advertisment collected.");
                    break;
                case BEACON:
                    // ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Beacon request collected.");

                    // Get BSSID
                    memcpy(&bssid, &packet->payload[16], 6);

                    exists = check_station_exists((char *)&packet->payload[16]);

                    if(!exists) {
                        add_station(packet);
                    }
#ifdef DEBUG
                    // Get ESSID 
                    length = packet->payload[37];
                    if(length != 0) {
                        memcpy(&essid, &packet->payload[38], length);
                        essid[length] = 0x00;
                    }              
                    ESP_LOGI(SNIFFER_TAG, "[SNIFFER] BSSID is %02x:%02x:%02x:%02x:%02x:%02x and SSID is: %s.", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], essid);
#endif
                    break;
                case DISASSOCIATION:
                    // ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Disassociation request collected.");
                    break;
                case DEAUTHENTICATION:
                    // ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Deauthentication request collected.");
                    break;
                case AUTHENTICATION:
                    // ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Authentication request collected.");
                    break;
                case ACTION:
                    // ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Action request collected");
                    break;
                case ASSOCIATION_RESPONSE:
                    // ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Association response collected");
                    break;
                case REASSOCIATION_RESPONSE:
                    // ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Reassociation response collected");
                    break;
                case PROBE_RESPONSE:
                    // ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Probe response collected");
                    break;
            }
            break;
        case DATA:
            ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Data frame collected - this shouldn't happen.");
            break;
        case CONTROL:
            ESP_LOGI(SNIFFER_TAG, "[SNIFFER] Control frame collected - this shouldn't happen.");    
    }

#endif

} 