#include "sniffer.h"

QueueHandle_t packet_queue = NULL;
TaskHandle_t xHandle_write = NULL;
TaskHandle_t xHandle_sniff = NULL;
TaskHandle_t xHandle_hop = NULL;

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

void handle_beacon(void *buf) {
    wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t*)buf;
    
    
#ifdef EXTRACT_PACKET

    uint8_t type;
    uint8_t subtype;
    uint8_t length;
    char ssid[33];

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
                    length = packet->payload[37];
                    if(length != 0) {
                        memcpy(&ssid, &packet->payload[38], length);
                        ssid[length] = 0x00;
                    }                    
                    ESP_LOGI(SNIFFER_TAG, "[SNIFFER] SSID is: %s.", ssid);
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