// (c) 2018 HomeAccessoryKid

#include <stdio.h>
#include <espressif/esp_wifi.h>
#include <espressif/esp_sta.h>
// //#include <espressif/esp_system.h> //for timestamp report only
// #include <esp/uart.h>
#include <esp8266.h>
#include <FreeRTOS.h>
#include <task.h>
#include <string.h>
#include "lwip/api.h"

#include <udplogger.h>

char udplogstring[1450]={0}; //in the end I do not know to prevent overflow, so I use the max size of 1 UDP packet

void udplog_send(void *pvParameters){
    struct netconn* conn;
    int i=0,len;
    
    while (sdk_wifi_station_get_connect_status() != STATION_GOT_IP) vTaskDelay(20); //Check if we have an IP every 200ms 
    // Create UDP connection
    conn = netconn_new(NETCONN_UDP);
    if (netconn_bind(   conn, IP_ADDR_ANY,       44444) != ERR_OK) netconn_delete(conn);
    if (netconn_connect(conn, IP_ADDR_BROADCAST, 45678) != ERR_OK) netconn_delete(conn);
    
    while(1){
        len=strlen(udplogstring);
        if ((!i && len) || len>1000) {
            struct netbuf* buf = netbuf_new();
            void* data = netbuf_alloc(buf,len);
            memcpy (data,udplogstring,len);
            udplogstring[0]=0; //there is a risk of new LOG to add to string after we measured len
            if (netconn_send(conn, buf) == ERR_OK) netbuf_delete(buf);
            i=10;
        }
        if (!i) i=10; //sends output every 100ms if not more than 1000 bytes
        i--;
        vTaskDelay(1); //with len>1000 and delay=10ms, we might handle 800kbps throughput
    }
}
