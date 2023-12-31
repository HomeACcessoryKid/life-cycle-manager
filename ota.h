/*  (c) 2018-2022 HomeAccessoryKid */
#ifndef __OTA_H__
#define __OTA_H__

#ifndef OTAVERSION
 #error You must set OTAVERSION=x.y.z of the ota code to match github version tag x.y.z
#endif
#define OTAREPO  "HomeACcessoryKid/life-cycle-manager"
//#define LCMREPO  "HomeACcessoryKid/life-cycle-manager"
#define BTLREPO  "HomeACcessoryKid/rboot4lcm"
#define BTLFILE "rboot.bin"
#define MAINFILE "otamain.bin"
#define BOOTFILE "otaboot.bin"
#define CERTFILE "certs.sector"
#define HAAREPO "RavenSystem/haa"
#define HAAFILE "haa_lcm.bin"
#define HOLDOFF_MULTIPLIER 20   //more like 20  -> 20s,400 (~6min),8000 (~2h),160000 (~2days)
#define HOLDOFF_MAX 604800      //more like 604800 (1 week)
#define BLINKDELAY 250
#define EMERGENCY "emergency"

#define SECTORSIZE 4096
#define HIGHERCERTSECTOR 0xFA000
#define LOWERCERTSECTOR 0xF9000
#define SYSPARAMSECTOR 0xF7000
#define BOOT0SECTOR 0x02000
#define BOOT1SECTOR 0x8D000 //must match the program1.ld value!!
#define HOST "github.com"
#define HTTPS_PORT 443
#define HTTP_PORT   80
#define FAILED "failed\n"
#define REQUESTHEAD "GET /"
#define REQUESTTAIL " HTTP/1.1\r\nHost: "
#define CRLFCRLF "\r\n\r\n"
#define RECV_BUF_LEN 1025  // current length of amazon URL 724
#define RANGE "\r\nRange: bytes="
#define MAXVERSIONLEN 16
#define SNTP_SERVERS 	"0.pool.ntp.org", "1.pool.ntp.org", "2.pool.ntp.org", "3.pool.ntp.org"

#define ECDSAKEYLENGTHMAX 128 //to be verified better, example is 120 bytes secP384r1
#define HASHSIZE  48  //SHA-384
#define SIGNSIZE 104  //ECDSA r+s in ASN1 format secP384r1
#define PKEYSIZE 120  //size of a pub key
#define KEYNAME "public-%d.key"
#define KEYNAMELEN 17 //allows for 65535 keys with uint16_t

typedef unsigned char byte;

typedef struct {
    byte hash[HASHSIZE];
    unsigned int   size; //32 bit
    byte sign[SIGNSIZE];
} signature_t;

int active_cert_sector;
int backup_cert_sector;

void  ota_read_rtc();

void  ota_active_sector();

void  ota_init();

int   ota_get_privkey();

int   ota_get_pubkey(int sector); //get the ecdsa key from the active_cert_sector

int   ota_verify_pubkey(void); //check if public and private key are a pair

void  ota_sign(int start_sector, int num_sectors, signature_t* signature, char* file);

int   ota_compare(char* newv, char* oldv);

int   ota_load_user_app(char * *repo, char * *version, char * *file);

void  ota_set_verify(int onoff);

void  ota_copy_bootloader(int sector, int size, char * version);

char* ota_get_btl_version();

char* ota_get_version(char * repo);

int   ota_get_file(char * repo, char * version, char * file, int sector); //number of bytes 

void  ota_finalize_file(int sector);

int   ota_get_newkey(char * repo, char * version, char * file, signature_t* signature);

int   ota_get_hash(char * repo, char * version, char * file, signature_t* signature);

int   ota_verify_hash(int address, signature_t* signature);
    
int   ota_verify_signature(signature_t* signature);

void  ota_swap_cert_sector();

void  ota_write_status(char * version);

int   ota_boot(void);

void  ota_temp_boot(void);

void  ota_reboot(void);

int   ota_emergency(char * *ota_srvr);

#endif // __OTA_H__
