// (c) 2018 HomeAccessoryKid
#ifndef __UDPLOGGER_H__
#define __UDPLOGGER_H__

//use nc -kulnw0 34567 to collect this output
//and use     xTaskCreate(udplog_send, "logsend", 256, NULL, 4, NULL); //is prio4 a good idea??

#define UDPLOG(message, ...)  sprintf(udplogstring+strlen(udplogstring),message, ##__VA_ARGS__)
void udplog_send(void *pvParameters);
extern char udplogstring[];

#endif //__UDPLOGGER_H__
