/*  (c) 2018-2022 HomeAccessoryKid */
#include <stdlib.h>  //for UDPLGP
#include <stdio.h>
#include <string.h>

#include <espressif/esp_common.h>
#include <lwip/sockets.h>
#include <lwip/api.h>
#include <esp8266.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>	    // needed by wolfSSL_check_domain_name()
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <ota.h>

#include <sntp.h>
//#include <time.h> //included in sntp.h
#include <spiflash.h>
#include <sysparam.h>
#include <rboot-api.h>

#include <udplogger.h>

static int  verify = 1;
static byte file_first_byte[]={0xff};
ecc_key prvecckey;
ecc_key pubecckey;

WOLFSSL_CTX* ctx;

#ifdef DEBUG_WOLFSSL    
void MyLoggingCallback(const int logLevel, const char* const logMessage) {
    /*custom logging function*/
    UDPLGP("loglevel: %d - %s\n",logLevel, logMessage);
}
#endif

bool userbeta=0;
bool otabeta=0;

char *ota_strstr(const char *full_string, const char *search) { //lowercase version of strstr()
    char *lc_string = strdup(full_string);
    unsigned char *ch = (unsigned char *) lc_string;
    while(*ch) {
        *ch = tolower(*ch);
        ch++;
    }
    const char *found = strstr(lc_string, search);
    free(lc_string);
    if(found == NULL) return NULL;    
    const int offset = (int) found - (int) lc_string;
    
    return (char *) ((int) full_string + offset);
}

void  ota_read_rtc() {
    UDPLGP("--- ota_read_rtc\n");
	int sector,count=0,user_count=0;
	int count_step=3;
    sysparam_status_t status;
    char *value=NULL;
    bool reset_wifi=0;
    bool reset_otabeta=0;
    bool factory_reset=0;
	rboot_rtc_data rtc;

    status = sysparam_init(SYSPARAMSECTOR, 0);
    if (status == SYSPARAM_OK) {
        status = sysparam_get_string("ota_count_step", &value);
        if (status == SYSPARAM_OK) {
            if (*value<0x34 && *value>0x30 && strlen(value)==1) count_step=*value-0x30;
            free(value);
        }
        status = sysparam_get_string("ota_count", &value);
        if (status == SYSPARAM_OK) {
            user_count=atoi(value);
            sysparam_set_string("ota_count","");
            free(value);
        }
    }
    UDPLGP("--- count_step=%d\n",count_step);
    
	if (rboot_get_rtc_data(&rtc)) count=rtc.temp_rom;
	if (count<2) count=user_count;
    
    UDPLGP("--- count=%d\n",count);
    if      (count<5+count_step*1) { //standard ota-main or ota-boot behavior
            value="--- standard ota";
    }
    else if (count<5+count_step*2) { //reset wifi parameters and clear LCM_beta
            value="--- reset wifi and clear LCM_beta";
            reset_wifi=1;
            reset_otabeta=1;
    }
    else if (count<5+count_step*3) { //reset wifi parameters and set LCM_beta
            value="--- reset wifi and set LCM_beta";
            reset_wifi=1;
            otabeta=1;
    }
    else    {//factory reset
            value="--- factory reset";
            factory_reset=1;
    }
    UDPLGP("%s\n",value);
    if (count>4) {
        UDPLGP("IF this is NOT what you wanted, reset/power-down NOW!\n");
        for (int i=9;i>-1;i--) {
            vTaskDelay(1000/portTICK_PERIOD_MS);
            UDPLGP("%s in %d s\n",value,i);
        }
    }
    if (factory_reset) {
        spiflash_erase_sector(SYSPARAMSECTOR);    spiflash_erase_sector(SYSPARAMSECTOR+SECTORSIZE);//sysparam reset
        for (sector=0xfb000; sector<   0x100000; sector+=SECTORSIZE) spiflash_erase_sector(sector);//Espressif area
        #ifndef OTABOOT    
         for(sector= 0x2000; sector<BOOT1SECTOR; sector+=SECTORSIZE) spiflash_erase_sector(sector);//user space
        #endif
    }

    uint32_t base_addr;
    uint32_t num_sectors;  

    status = sysparam_init(SYSPARAMSECTOR, 0);
    if (status != SYSPARAM_OK) {
        status = sysparam_create_area(SYSPARAMSECTOR, 2, true);
        if (status == SYSPARAM_OK) {
            status = sysparam_init(SYSPARAMSECTOR, 0);
        }
    } else {
        sysparam_get_info(&base_addr, &num_sectors);
        if (num_sectors!=2) {
            status = sysparam_create_area(SYSPARAMSECTOR, 2, true);
            if (status == SYSPARAM_OK) {
                status = sysparam_init(SYSPARAMSECTOR, 0);
            }
        }
    }
    if (status != SYSPARAM_OK) {
        printf("WARNING: LCM/OTA could not initialize sysparams (%d)!\n", status);
    }
    if (reset_wifi) {
        sysparam_set_string("wifi_ssid","");
        sysparam_set_string("wifi_password","");
        sysparam_compact(); //to make a copy without the ssid/password (does not erase old region)
        sysparam_compact(); //to make sure the information really gets wiped
        struct sdk_station_config sta_config; //remove esp wifi client settings
        memset(&sta_config, 0, sizeof(sta_config));
        sdk_wifi_station_set_config(&sta_config); //This wipes out the info in sectors 0xfd000+
    }
    #ifdef OTABETA
    otabeta=1; //using beta = pre-releases?
    #endif
    if (otabeta && !reset_otabeta) sysparam_set_bool("lcm_beta", 1);
    if (            reset_otabeta) sysparam_set_data("lcm_beta", NULL,0,0);
}

void  ota_active_sector() {
    UDPLGP("--- ota_active_sector: ");
    extern int active_cert_sector;
    extern int backup_cert_sector;
    // set active_cert_sector
    // first byte of the sector is its state:
    // 0xff backup being evaluated
    // 0x30 active sector
    // 0x00 deactivated
    byte fourbyte[4];
    active_cert_sector=HIGHERCERTSECTOR;
    backup_cert_sector=LOWERCERTSECTOR;
    if (!spiflash_read(active_cert_sector, (byte *)fourbyte, 4)) { //get first 4 active
        UDPLGP("error reading flash\n");
    } // if OTHER  vvvvvv sector active
    if (fourbyte[0]!=0x30 || fourbyte[1]!=0x76 || fourbyte[2]!=0x30 || fourbyte[3]!=0x10 ) {
        active_cert_sector=LOWERCERTSECTOR;
        backup_cert_sector=HIGHERCERTSECTOR;
        if (!spiflash_read(active_cert_sector, (byte *)fourbyte, 4)) {
            UDPLGP("error reading flash\n");
        }
        if (fourbyte[0]!=0x30 || fourbyte[1]!=0x76 || fourbyte[2]!=0x30 || fourbyte[3]!=0x10 ) {
#ifdef OTABOOT
            #include "certs.h"
            active_cert_sector=HIGHERCERTSECTOR;
            backup_cert_sector=LOWERCERTSECTOR;
            spiflash_erase_sector(active_cert_sector); //just in case
            spiflash_write(active_cert_sector, certs_sector, certs_sector_len);
#else
            active_cert_sector=0;
            backup_cert_sector=0;
#endif
        }
    }
    UDPLGP("0x%x\n",active_cert_sector);
}

int8_t led=16;
TaskHandle_t ledblinkHandle = NULL;
void   led_blink_task(void *pvParameter) {
    UDPLGP("--- led_blink_task");
    if (led<6 || led>11) { //do not allow pins 6-11
        UDPLGP(" blinking led pin %d\n",led);
        gpio_enable(led, GPIO_OUTPUT);
        while(1) {
            gpio_write(led, 1); vTaskDelay(BLINKDELAY/portTICK_PERIOD_MS);
            gpio_write(led, 0); vTaskDelay(BLINKDELAY/portTICK_PERIOD_MS);
        }
    } else {
        UDPLGP(": invalid pin %d\n",led);
    }
    ledblinkHandle = NULL;
    vTaskDelete(NULL);
}

void  ota_init() {
    UDPLGP("--- ota_init\n");

    sysparam_get_bool("lcm_beta", &otabeta);
    sysparam_get_bool("ota_beta", &userbeta);
    UDPLGP("userbeta=\'%d\' otabeta=\'%d\'\n",userbeta,otabeta);

    ip_addr_t target_ip;
    int ret;
    
    sysparam_status_t status;
    uint8_t led_info=0;

    status = sysparam_get_int8("led_pin", &led);
    if (status == SYSPARAM_OK) {
        if (led<0) {led_info=0x10; led=-led;}
        led_info+=(led<16)?(0x40+(led&0x0f)):0;
        if (led<16) xTaskCreate(led_blink_task, "ledblink", 256, NULL, 1, &ledblinkHandle);
    }

    //rboot setup
    rboot_config conf;
    conf=rboot_get_config();
    UDPLGP("rboot_config.unused[1]=LEDinfo from 0x%02x to 0x%02x\n",conf.unused[1],led_info);
    if (conf.count!=2 || conf.roms[0]!=BOOT0SECTOR || conf.roms[1]!=BOOT1SECTOR || conf.current_rom!=0 || conf.unused[1]!=led_info) {
        conf.count =2;   conf.roms[0] =BOOT0SECTOR;   conf.roms[1] =BOOT1SECTOR;   conf.current_rom =0;   conf.unused[1] =led_info;
        rboot_set_config(&conf);
    }
    
    //time support
    const char *servers[] = {SNTP_SERVERS};
	sntp_set_update_delay(24*60*60000); //SNTP will request an update every 24 hour
	//const struct timezone tz = {1*60, 0}; //Set GMT+1 zone, daylight savings off
	//sntp_initialize(&tz);
	sntp_initialize(NULL);
	sntp_set_servers(servers, sizeof(servers) / sizeof(char*)); //Servers must be configured right after initialization

#ifdef DEBUG_WOLFSSL    
    if (wolfSSL_SetLoggingCb(MyLoggingCallback)) UDPLGP("error setting debug callback\n");
#endif
    
    wolfSSL_Init();

    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx) {
        //error
    }
    ota_active_sector();
    ota_set_verify(0);
    UDPLGP("--- DNS: ");
    ret = netconn_gethostbyname(HOST, &target_ip);
    while(ret) {
        UDPLGP("%d",ret);
        vTaskDelay(200);
        ret = netconn_gethostbyname(HOST, &target_ip);
    }
    UDPLGP("done!\n");
}

#ifdef OTABOOT    
int ota_get_privkey() {
    UDPLGP("--- ota_get_privkey\n");
    
    byte buffer[PKEYSIZE]; //maybe 49 bytes would be enough
    int ret;
    unsigned int idx;
    int length;
    
    //load private key as produced by openssl
    if (!spiflash_read(backup_cert_sector, (byte *)buffer, 24)) {
        UDPLGP("error reading flash\n");    return -1;
    }
    if (buffer[0]!=0x30 || buffer[1]!=0x81) return -2; //not a valid keyformat
    if (buffer[3]!=0x02 || buffer[4]!=0x01 || buffer[5]!=0x01) return -2; //not a valid keyformat
    if (buffer[6]!=0x04) return -2; //not a valid keyformat
    idx=7;
    length=buffer[idx++]; //bitstring start
    
    if (!spiflash_read(backup_cert_sector+idx, (byte *)buffer, length)) {
        UDPLGP("error reading flash\n");    return -1;
    }
    for (idx=0;idx<length;idx++) printf(" %02x",buffer[idx]);
    wc_ecc_init(&prvecckey);
    ret=wc_ecc_import_private_key_ex(buffer, length, NULL, 0, &prvecckey,ECC_SECP384R1);
    printf("\nret: %d\n",ret);
    
    /*
    */
    return ret;
}
#endif

int ota_get_pubkey(int sector) { //get the ecdsa key from the indicated sector, report filesize
    UDPLGP("--- ota_get_pubkey\n");
    
    byte buf[PKEYSIZE];
    byte * buffer=buf;
    int length,ret;
    //load public key as produced by openssl
    if (!spiflash_read(sector, (byte *)buffer, PKEYSIZE)) {
        UDPLGP("error reading flash\n");    return -1;
    }
    //do not test the first byte since else the key-update routine will not be able to collect a key
    if (buffer[ 1]!=0x76 || buffer[ 2]!=0x30 || buffer[ 3]!=0x10) return -2; //not a valid keyformat
    if (buffer[20]!=0x03 || buffer[21]!=0x62 || buffer[22]!=0x00) return -2; //not a valid keyformat
    length=97;
    
    int idx; for (idx=0;idx<length;idx++) printf(" %02x",buffer[idx+23]);
    wc_ecc_init(&pubecckey);
    ret=wc_ecc_import_x963_ex(buffer+23,length,&pubecckey,ECC_SECP384R1);
    printf("\n");
    UDPLGP("ret: %d\n",ret);

    if (!ret)return PKEYSIZE; else return ret;
}

#ifdef OTABOOT    
int ota_verify_pubkey(void) { //check if public and private key are a pair
    UDPLGP("--- ota_verify_pubkey\n");
    
    byte hash[HASHSIZE];
    WC_RNG rng;
    wc_RNG_GenerateBlock(&rng, hash, HASHSIZE);
    //int i; printf("hash: "); for (i=0;i<HASHSIZE;i++) printf("%02x ",hash[i]); printf("\n");
    
    int answer;
    unsigned int siglen=SIGNSIZE;
    byte signature[SIGNSIZE];

    wc_ecc_sign_hash(hash, HASHSIZE, signature, &siglen, &rng, &prvecckey);
    wc_ecc_verify_hash(signature, siglen, hash, HASHSIZE, &answer, &pubecckey);
    
    UDPLGP("key valid: %d\n",answer);
        
    return answer-1;
}
#endif

void ota_hash(int start_sector, int filesize, byte * hash, byte first_byte) {
    UDPLGP("--- ota_hash\n");
    
    int bytes;
    byte buffer[1024];
    Sha384 sha;
    
    wc_InitSha384(&sha);
    //printf("bytes: ");
    for (bytes=0;bytes<filesize-1024;bytes+=1024) {
        //printf("%d ",bytes);
        if (!spiflash_read(start_sector+bytes, (byte *)buffer, 1024)) {
            UDPLGP("error reading flash\n");   break;
        }
        if (!bytes && first_byte!=0xff) buffer[0]=first_byte;
        wc_Sha384Update(&sha, buffer, 1024);
    }
    //printf("%d\n",bytes);
    if (!spiflash_read(start_sector+bytes, (byte *)buffer, filesize-bytes)) {
        UDPLGP("error reading flash @ %d for %d bytes\n",start_sector+bytes,filesize-bytes);
    }
    if (!bytes && first_byte!=0xff) buffer[0]=first_byte;
    //printf("filesize %d\n",filesize);
    wc_Sha384Update(&sha, buffer, filesize-bytes);
    wc_Sha384Final(&sha, hash);
}

#ifdef OTABOOT    
void ota_sign(int start_sector, int filesize, signature_t* signature, char* file) {
    UDPLGP("--- ota_sign\n");
    
    unsigned int i,siglen=SIGNSIZE;
    WC_RNG rng;

    ota_hash(start_sector, filesize, signature->hash, 0xff); // 0xff=no special first byte action
    wc_ecc_sign_hash(signature->hash, HASHSIZE, signature->sign, &siglen, &rng, &prvecckey);
    printf("echo "); for (i=0;i<HASHSIZE;i++) printf("%02x ",signature->hash[i]); printf("> x.hex\n");
    printf("echo %08x >>x.hex\n",filesize);
    printf("echo "); for (i=0;i<siglen  ;i++) printf("%02x ",signature->sign[i]); printf(">>x.hex\n");
    printf("xxd -r -p x.hex > %s.sig\n",file);  printf("rm x.hex\n");
}
#endif

int ota_compare(char* newv, char* oldv) { //(if equal,0) (if newer,1) (if pre-release or older,-1)
    UDPLGP("--- ota_compare ");
    printf("\n");
    char* dot;
    int valuen=0,valueo=0;
    char news[MAXVERSIONLEN],olds[MAXVERSIONLEN];
    char * new=news;
    char * old=olds;
    int result=0;
    
    if (strcmp(newv,oldv)) { //https://semver.org/#spec-item-11
        do {
            if (strchr(newv,'-')) {result=-1;break;} //we cannot handle versions with pre-release suffix notation (yet)
            //pre-release marker in github serves to identify those
            strncpy(new,newv,MAXVERSIONLEN-1);
            strncpy(old,oldv,MAXVERSIONLEN-1);
            if ((dot=strchr(new,'.'))) {dot[0]=0; valuen=atoi(new); new=dot+1;}
            if ((dot=strchr(old,'.'))) {dot[0]=0; valueo=atoi(old); old=dot+1;}
            printf("%d-%d,%s-%s\n",valuen,valueo,new,old);
            if (valuen>valueo) {result= 1;break;}
            if (valuen<valueo) {result=-1;break;}
            valuen=valueo=0;
            if ((dot=strchr(new,'.'))) {dot[0]=0; valuen=atoi(new); new=dot+1;}
            if ((dot=strchr(old,'.'))) {dot[0]=0; valueo=atoi(old); old=dot+1;}
            printf("%d-%d,%s-%s\n",valuen,valueo,new,old);
            if (valuen>valueo) {result= 1;break;}
            if (valuen<valueo) {result=-1;break;}
            valuen=atoi(new);
            valueo=atoi(old);
            printf("%d-%d\n",valuen,valueo);
            if (valuen>valueo) {result= 1;break;}
            if (valuen<valueo) {result=-1;break;}        
        } while(0);
    } //they are equal
    UDPLGP("%s with %s=%d\n",newv,oldv,result);
    return result;
}

int local_port=0;
static int ota_connect(char* host, int port, int *socket, WOLFSSL** ssl) {
    UDPLGP("--- ota_connect LocalPort=");
    int ret;
    ip_addr_t target_ip;
    struct sockaddr_in sock_addr;
    unsigned char initial_port[2];
    WC_RNG rng;
    
    if (!local_port) {
        wc_RNG_GenerateBlock(&rng, initial_port, 2);
        local_port=(256*initial_port[0]+initial_port[1])|0xc000;
    }
    UDPLGP("%04x DNS",local_port);
    ret = netconn_gethostbyname(host, &target_ip);
    while(ret) {
        printf("%d",ret);
        vTaskDelay(200);
        ret = netconn_gethostbyname(host, &target_ip);
    }
    UDPLGP(" IP:%d.%d.%d.%d ", (unsigned char)((target_ip.addr & 0x000000ff) >> 0),
                              (unsigned char)((target_ip.addr & 0x0000ff00) >> 8),
                              (unsigned char)((target_ip.addr & 0x00ff0000) >> 16),
                              (unsigned char)((target_ip.addr & 0xff000000) >> 24));
    //printf("create socket ......");
    *socket = socket(AF_INET, SOCK_STREAM, 0);
    if (*socket < 0) {
        UDPLGP(FAILED);
        return -3;
    }

    UDPLGP("local..");
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = 0;
    sock_addr.sin_port = htons(local_port++);
    if (local_port==0x10000) local_port=0xc000;
    ret = bind(*socket, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    if (ret) {
        UDPLGP(FAILED);
        return -2;
    }
    UDPLGP("OK ");

    UDPLGP("remote..");
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = target_ip.addr;
    sock_addr.sin_port = htons(port);
    ret = connect(*socket, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    if (ret) {
        UDPLGP(FAILED);
        return -2;
    }
    UDPLGP("OK ");

    if (port==HTTPS_PORT) { //SSL mode, in emergency mode this is skipped
    UDPLGP("SSL..");
    *ssl = wolfSSL_new(ctx);
    if (!*ssl) {
        UDPLGP(FAILED);
        return -2;
    }
    UDPLGP("OK ");

//wolfSSL_Debugging_ON();
    wolfSSL_set_fd(*ssl, *socket);
    UDPLGP("set_fd ");

    ret = wolfSSL_UseSNI(*ssl, WOLFSSL_SNI_HOST_NAME, host, strlen(host));
    if (ret != SSL_SUCCESS) {
        UDPLGP("failed, return [-0x%x]\n", -ret);
        ret=wolfSSL_get_error(*ssl,ret);
        UDPLGP("wolfSSL_UseSNI error = %d\n", ret);
        return -1;
    }

    if (verify) ret=wolfSSL_check_domain_name(*ssl, host);
//wolfSSL_Debugging_OFF();

    UDPLGP("to %s port %d..", host, port);
    ret = wolfSSL_connect(*ssl);
    if (ret != SSL_SUCCESS) {
        UDPLGP("failed, return [-0x%x]\n", -ret);
        ret=wolfSSL_get_error(*ssl,ret);
        UDPLGP("wolfSSL_send error = %d\n", ret);
        return -1;
    }
    UDPLGP("OK\n");
    } //end SSL mode
    return 0;

}

int   ota_load_user_app(char * *repo, char * *version, char * *file) {
    UDPLGP("--- ota_load_user_app\n");
    sysparam_status_t status;
    char *value;

    status = sysparam_get_string("ota_repo", &value);
    if (status == SYSPARAM_OK) {
        *repo=value;
    } else return -1;
    status = sysparam_get_string("ota_version", &value);
    if (status == SYSPARAM_OK) {
        *version=value;
    } else {
        *version=malloc(6);
        strcpy(*version,"0.0.0");
    }
    status = sysparam_get_string("ota_file", &value);
    if (status == SYSPARAM_OK) {
        *file=value;
    } else return -1;

    UDPLGP("user_repo=\'%s\' user_version=\'%s\' user_file=\'%s\'\n",*repo,*version,*file);
    return 0;
}

void  ota_set_verify(int onoff) {
    UDPLGP("--- ota_set_verify...");
    int ret=0;
    byte abyte[1];
    
    if (onoff) {
        UDPLGP("ON\n");
        if (verify==0) {
            verify= 1;
            do {
                if (!spiflash_read(active_cert_sector+PKEYSIZE+(ret++), (byte *)abyte, 1)) {
                    UDPLGP("error reading flash\n");
                    break;
                }
            } while (abyte[0]!=0xff); ret--;
            UDPLGP("certs size: %d\n",ret);
            byte *certs=malloc(ret);
            spiflash_read(active_cert_sector+PKEYSIZE, (byte *)certs, ret);

            ret=wolfSSL_CTX_load_verify_buffer(ctx, certs, ret, SSL_FILETYPE_PEM);
            if ( ret != SSL_SUCCESS) {
                UDPLGP("fail cert loading, return %d\n", ret);
            }
            free(certs);
            
            time_t ts;
            do {
                ts = time(NULL);
                if (ts == ((time_t)-1)) printf("ts=-1, ");
                vTaskDelay(1);
            } while (!(ts>1073741823)); //2^30-1 which is supposed to be like 2004
            UDPLGP("TIME: %s", ctime(&ts)); //we need to have the clock right to check certificates
            
            wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        }
    } else {
        UDPLGP("OFF\n");
        if (verify==1) {
            verify= 0;
            wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        }
    }
}

void  ota_copy_bootloader(int sector, int size, char * version) {
    UDPLGP("--- ota_copy_bootloader\n");
    byte buffer[SECTORSIZE];
    byte fourbyte[4];
    char versionbuff[MAXVERSIONLEN];
    
    memset(versionbuff,0xff,MAXVERSIONLEN);
    strcpy(versionbuff,version);
    spiflash_read(sector, buffer, size);
    spiflash_read(0, fourbyte, 4); //transfer the flash setting flags from previous boot sector...
    buffer[2]=fourbyte[2]; buffer[3]=fourbyte[3];
    spiflash_erase_sector(0);
    spiflash_write(0, buffer, size);
    //version is stored as a string in last MAXVERSIONLEN bytes of sector
    spiflash_write(SECTORSIZE-MAXVERSIONLEN, (byte *)versionbuff, MAXVERSIONLEN);
    //set last uint32 to zero of the config sector so rboot will reflash it
    memset(versionbuff,0,4);
    spiflash_write(2*SECTORSIZE-4, (byte *)versionbuff, 4);
}

char* ota_get_btl_version() {
    UDPLGP("--- ota_get_btl_version\n");
    char versionbuff[MAXVERSIONLEN];
    char* version=NULL;
    
    spiflash_read(SECTORSIZE-MAXVERSIONLEN, (byte *)versionbuff, MAXVERSIONLEN);
    if (versionbuff[0]!=0xff) { //TODO: make this more error resistant
        version=malloc(strlen(versionbuff));
        strcpy(version,versionbuff);
    } else {
        version=malloc(6);
        strcpy(version,"0.0.0");
    }
    UDPLGP("bootloader version:\"%s\"\n",version);
    return version;
}

int   ota_get_file_ex(char * repo, char * version, char * file, int sector, byte * buffer, int bufsz); //prototype needed
char* ota_get_version(char * repo) {
    UDPLGP("--- ota_get_version\n");

    char* version=NULL;
    char prerelease[64]; 
    int retc, ret=0;
    int httpcode;
    WOLFSSL*     ssl;
    int socket;
    //host=begin(repo);
    //mid =end(repo)+blabla+version
    char* found_ptr;
    char recv_buf[RECV_BUF_LEN];
    int  send_bytes; //= sizeof(send_data);
    
    strcat(strcat(strcat(strcat(strcat(strcpy(recv_buf, \
        REQUESTHEAD),repo),"/releases/latest"),REQUESTTAIL),HOST),CRLFCRLF);
    send_bytes=strlen(recv_buf);
    //printf("%s\n",recv_buf);

    retc = ota_connect(HOST, HTTPS_PORT, &socket, &ssl);  //release socket and ssl when ready
    
    if (!retc) {
        UDPLGP("%s",recv_buf);
        ret = wolfSSL_write(ssl, recv_buf, send_bytes);
        if (ret > 0) {
            printf("sent OK\n");

            ret = wolfSSL_peek(ssl, recv_buf, RECV_BUF_LEN - 1);
            if (ret > 0) {
                recv_buf[ret]=0; //prevent falling of the end of the buffer when doing string operations
                found_ptr=ota_strstr(recv_buf,"http/1.1 ");
                found_ptr+=9; //flush "HTTP/1.1 "
                httpcode=atoi(found_ptr);
                UDPLGP("HTTP returns %d for ",httpcode);
                if (httpcode!=302) {
                    wolfSSL_free(ssl);
                    lwip_close(socket);
                    return "404";
                }
            } else {
                UDPLGP("failed, return [-0x%x]\n", -ret);
                ret=wolfSSL_get_error(ssl,ret);
                UDPLGP("wolfSSL_send error = %d\n", ret);
                return "404";
            }

            while (1) {
                recv_buf[ret]=0; //prevent falling of the end of the buffer when doing string operations
                found_ptr=ota_strstr(recv_buf,"\nlocation:");
                if (found_ptr) break;
                wolfSSL_read(ssl, recv_buf, RECV_BUF_LEN - 12);
                ret = wolfSSL_peek(ssl, recv_buf, RECV_BUF_LEN - 1);
                if (ret <= 0) {
                    UDPLGP("failed, return [-0x%x]\n", -ret);
                    ret=wolfSSL_get_error(ssl,ret);
                    UDPLGP("wolfSSL_send error = %d\n", ret);
                    return "404";
                }
            }
            ret=wolfSSL_read(ssl, recv_buf, found_ptr-recv_buf + 11); //flush all previous material
            ret=wolfSSL_read(ssl, recv_buf, RECV_BUF_LEN - 1); //this starts for sure with the content of "Location: "
            recv_buf[ret]=0; //prevent falling of the end of the buffer when doing string operations
            strchr(recv_buf,'\r')[0]=0;
            found_ptr=ota_strstr(recv_buf,"releases/tag/");
            if (found_ptr[13]=='v' || found_ptr[13]=='V') found_ptr++;
            version=malloc(strlen(found_ptr+13));
            strcpy(version,found_ptr+13);
            printf("%s@version:\"%s\" according to latest release\n",repo,version);
        } else {
            UDPLGP("failed, return [-0x%x]\n", -ret);
            ret=wolfSSL_get_error(ssl,ret);
            UDPLGP("wolfSSL_send error = %d\n", ret);
        }
    }
    switch (retc) {
        case  0:
        case -1:
        wolfSSL_free(ssl);
        case -2:
        lwip_close(socket);
        case -3:
        default:
        ;
    }

//     if (retc) return retc;
//     if (ret <= 0) return ret;

    //TODO: maybe add more error return messages... like version "99999.99.99"
    //find latest-pre-release if joined beta program
    bool OTAorBTL=!(strcmp(OTAREPO,repo)&&strcmp(BTLREPO,repo));
    if ( (userbeta && !OTAorBTL) || (otabeta && OTAorBTL)) {
        prerelease[63]=0;
        ret=ota_get_file_ex(repo,version,"latest-pre-release",0,(byte *)prerelease,63);
        if (ret>0) {
            prerelease[ret]=0; //TODO: UNTESTED make a final 0x0a and or 0x0d optional
            if (prerelease[ret-1]=='\n') {
                prerelease[ret-1]=0;
                if (prerelease[ret-2]=='\r') prerelease[ret-2]=0;                
            }
            free(version);
            version=malloc(strlen(prerelease)+1);
            strcpy(version,prerelease);
        }
    }
    
    if (ota_boot() && ota_compare(version,OTAVERSION)<0) { //this acts when setting up a new version
        free(version);
        version=malloc(strlen(OTAVERSION)+1);
        strcpy(version,OTAVERSION);
    }
    
    UDPLGP("%s@version:\"%s\"\n",repo,version);
    return version;
}

int   ota_get_file_ex(char * repo, char * version, char * file, int sector, byte * buffer, int bufsz) { //number of bytes
    UDPLGP("--- ota_get_file_ex\n");
    
    int retc, ret=0, slash;
    WOLFSSL*     ssl;
    int socket;
    //host=begin(repo);
    //mid =end(repo)+blabla+version
    char* found_ptr=NULL;
    char recv_buf[RECV_BUF_LEN];
    int  recv_bytes = 0;
    int  send_bytes; //= sizeof(send_data);
    int  length=1;
    int  clength=0;
    int  left;
    int  collected=0;
    int  writespace=0;
    int  header;
    bool emergency=(strcmp(version,EMERGENCY))?0:1;
    int  port=(emergency)?HTTP_PORT:HTTPS_PORT;
    
    if (sector==0 && buffer==NULL) return -5; //needs to be either a sector or a signature
    
    if (!emergency) { //if not emergency, find the redirection done by GitHub
    strcat(strcat(strcat(strcat(strcat(strcat(strcat(strcat(strcpy(recv_buf, \
        REQUESTHEAD),repo),"/releases/download/"),version),"/"),file),REQUESTTAIL),HOST),CRLFCRLF);
    send_bytes=strlen(recv_buf);
    UDPLGP("%s",recv_buf);

    retc = ota_connect(HOST, HTTPS_PORT, &socket, &ssl);  //release socket and ssl when ready
    
    if (!retc) {
        ret = wolfSSL_write(ssl, recv_buf, send_bytes);
        if (ret > 0) {
            UDPLGP("sent OK\n");

            ret = wolfSSL_peek(ssl, recv_buf, RECV_BUF_LEN - 1);
            if (ret > 0) {
                recv_buf[ret]=0; //prevent falling of the end of the buffer when doing string operations
                found_ptr=ota_strstr(recv_buf,"http/1.1 ");
                found_ptr+=9; //flush "HTTP/1.1 "
                slash=atoi(found_ptr);
                UDPLGP("HTTP returns %d\n",slash);
                if (slash!=302) {
                    wolfSSL_free(ssl);
                    lwip_close(socket);
                    return -1;
                }
            } else {
                UDPLGP("failed, return [-0x%x]\n", -ret);
                ret=wolfSSL_get_error(ssl,ret);
                UDPLGP("wolfSSL_send error = %d\n", ret);
                return -1;
            }
            while (1) {
                recv_buf[ret]=0; //prevent falling of the end of the buffer when doing string operations
                found_ptr=ota_strstr(recv_buf,"\nlocation:");
                if (found_ptr) break;
                wolfSSL_read(ssl, recv_buf, RECV_BUF_LEN - 12);
                ret = wolfSSL_peek(ssl, recv_buf, RECV_BUF_LEN - 1);
                if (ret <= 0) {
                    UDPLGP("failed, return [-0x%x]\n", -ret);
                    ret=wolfSSL_get_error(ssl,ret);
                    UDPLGP("wolfSSL_send error = %d\n", ret);
                    return -1;
                }
            }
            ret=wolfSSL_read(ssl, recv_buf, found_ptr-recv_buf + 11); //flush all previous material
            ret=wolfSSL_read(ssl, recv_buf, RECV_BUF_LEN - 1); //this starts for sure with the content of "Location: "
            recv_buf[ret]=0; //prevent falling of the end of the buffer when doing string operations
            strchr(recv_buf,'\r')[0]=0;
            found_ptr=recv_buf;
            //if (found_ptr[0] == ' ') found_ptr++;
            found_ptr+=8; //flush https://
            //printf("location=%s\n",found_ptr);
        } else {
            UDPLGP("failed, return [-0x%x]\n", -ret);
            ret=wolfSSL_get_error(ssl,ret);
            UDPLGP("wolfSSL_send error = %d\n", ret);
        }
    }
    switch (retc) {
        case  0:
        case -1:
        wolfSSL_free(ssl);
        case -2:
        lwip_close(socket);
        case -3:
        default:
        ;
    }

    if (retc) return retc;
    if (ret <= 0) return ret;
    
    } else { //emergency mode, repo is expected to have the format "not.github.com/somewhere/"
        strcpy(recv_buf,repo);
        found_ptr=recv_buf;
        if (found_ptr[strlen(found_ptr)-1]!='/') strcat(found_ptr, "/");
        strcat(found_ptr, file);
        UDPLGP("emergency GET http://%s\n",found_ptr);
    } //found_ptr now contains the url without https:// or http://
    //process the Location
    strcat(found_ptr, REQUESTTAIL);
    slash=strchr(found_ptr,'/')-found_ptr;
    found_ptr[slash]=0; //cut behind the hostname
    char * host2=malloc(strlen(found_ptr));
    strcpy(host2,found_ptr);
    //printf("next host: %s\n",host2);

    retc = ota_connect(host2, port, &socket, &ssl);  //release socket and ssl when ready

    strcat(strcat(found_ptr+slash+1,host2),RANGE); //append hostname and range to URI    
    found_ptr+=slash-4;
    memcpy(found_ptr,REQUESTHEAD,5);
    char * getlinestart=malloc(strlen(found_ptr));
    strcpy(getlinestart,found_ptr);
    //printf("request:\n%s\n",getlinestart);
    //if (!retc) {
    while (collected<length) {
        sprintf(recv_buf,"%s%d-%d%s",getlinestart,collected,collected+4095,CRLFCRLF);
        send_bytes=strlen(recv_buf);
        //printf("request:\n%s\n",recv_buf);
        printf("send request......");
        if (emergency) ret = lwip_write(socket, recv_buf, send_bytes); else ret = wolfSSL_write(ssl, recv_buf, send_bytes);
        recv_bytes=0;
        if (ret > 0) {
            printf("OK\n");

            header=1;
            memset(recv_buf,0,RECV_BUF_LEN);
            //wolfSSL_Debugging_ON();
            do {
                if (emergency) ret = lwip_read(socket, recv_buf, RECV_BUF_LEN - 1); else ret = wolfSSL_read(ssl, recv_buf, RECV_BUF_LEN - 1);
                if (ret > 0) {
                    if (header) {
                        //printf("%s\n-------- %d\n", recv_buf, ret);
                        //parse Content-Length: xxxx
                        found_ptr=ota_strstr(recv_buf,"\ncontent-length:");
                        strchr(found_ptr,'\r')[0]=0;
                        found_ptr+=16; //flush Content-Length://
			            //if (found_ptr[0] == ' ') found_ptr++; //flush a space, atoi would also do that
                        clength=atoi(found_ptr);
                        found_ptr[strlen(found_ptr)]='\r'; //in case the order changes
                        //parse Content-Range: bytes xxxx-yyyy/zzzz
                        found_ptr=ota_strstr(recv_buf,"\ncontent-range:");
                        strchr(found_ptr,'\r')[0]=0;
                        found_ptr+=15; //flush Content-Range://
                        found_ptr=ota_strstr(recv_buf,"bytes ");
                        found_ptr+=6; //flush Content-Range: bytes //
                        found_ptr=strstr(found_ptr,"/"); found_ptr++; //flush /
                        length=atoi(found_ptr);
                        found_ptr[strlen(found_ptr)]='\r'; //search the entire buffer again
                        found_ptr=strstr(recv_buf,CRLFCRLF)+4; //go to end of header
                        if ((left=ret-(found_ptr-recv_buf))) {
                            header=0; //we have body in the same IP packet as the header so we need to process it already
                            ret=left;
                            memmove(recv_buf,found_ptr,left); //move this payload to the head of the recv_buf
                        }
                    }
                    if (!header) {
                        recv_bytes += ret;
                        if (sector) { //write to flash
                            if (writespace<ret) {
                                UDPLGP("erasing@0x%05x>", sector+collected);
                                if (!spiflash_erase_sector(sector+collected)) return -6; //erase error
                                writespace+=SECTORSIZE;
                            }
                            if (collected) {
                                if (!spiflash_write(sector+collected, (byte *)recv_buf,   ret  )) return -7; //write error
                            } else { //at the very beginning, do not write the first byte yet but store it for later
                                file_first_byte[0]=(byte)recv_buf[0];
                                if (!spiflash_write(sector+1        , (byte *)recv_buf+1, ret-1)) return -7; //write error
                            }
                            writespace-=ret;
                        } else { //buffer
                            if (ret>bufsz) return -8; //too big
                            memcpy(buffer,recv_buf,ret);
                        }
                        collected+=ret;
                        int i;
                        for (i=0;i<3;i++) printf("%02x", recv_buf[i]);
                        printf("...");
                        for (i=3;i>0;i--) printf("%02x", recv_buf[ret-i]);
                        printf(" ");
                    }
                } else {
                    if (ret && !emergency) {ret=wolfSSL_get_error(ssl,ret); UDPLGP("error %d\n",ret);}
                    if (!ret && collected<length) retc = ota_connect(host2, port, &socket, &ssl); //memory leak?
                    break;
                }
                header=0; //if header and body are separted
            } while(recv_bytes<clength);
            printf(" so far collected %d bytes\n", collected);
            UDPLOG(" collected %d bytes\r",        collected);
        } else {
            printf("failed, return [-0x%x]\n", -ret);
            if (!emergency) {
            ret=wolfSSL_get_error(ssl,ret);
            printf("wolfSSL_send error = %d\n", ret);
            }
            if (ret==-308) {
                retc = ota_connect(host2, port, &socket, &ssl); //dangerous for eternal connecting? memory leak?
            } else {
                break; //give up?
            }
        }
    }
    UDPLOG("\n");
    switch (retc) {
        case  0:
        case -1:
        if (!emergency) {
        wolfSSL_free(ssl);
        }
        case -2:
        lwip_close(socket);
        case -3:
        default:
        ;
    }
    free(host2);
    free(getlinestart);
    if (retc) return retc;
    if (ret < 0) return ret;
    return collected;
}

void  ota_finalize_file(int sector) {
    UDPLGP("--- ota_finalize_file\n");

    if (!spiflash_write(sector, file_first_byte, 1)) UDPLGP("error writing flash\n");
    //TODO: add verification and retry and if wrong return status...
}

int   ota_get_file(char * repo, char * version, char * file, int sector) { //number of bytes
    UDPLGP("--- ota_get_file\n");
    return ota_get_file_ex(repo,version,file,sector,NULL,0);
}

int   ota_get_hash(char * repo, char * version, char * file, signature_t* signature) {
    UDPLGP("--- ota_get_hash\n");
    int ret;
    byte buffer[HASHSIZE+4+SIGNSIZE];
    char * signame=malloc(strlen(file)+5);
    strcpy(signame,file);
    strcat(signame,".sig");
    memset(signature->hash,0,HASHSIZE);
    memset(signature->sign,0,SIGNSIZE);
    ret=ota_get_file_ex(repo,version,signame,0,buffer,HASHSIZE+4+SIGNSIZE);
    free(signame);
    if (ret<0) return ret;
    memcpy(signature->hash,buffer,HASHSIZE);
    signature->size=((buffer[HASHSIZE]*256 + buffer[HASHSIZE+1])*256 + buffer[HASHSIZE+2])*256 + buffer[HASHSIZE+3];
    if (ret>HASHSIZE+4) memcpy(signature->sign,buffer+HASHSIZE+4,SIGNSIZE);

    return 0;
}

int   ota_verify_hash(int address, signature_t* signature) {
    UDPLGP("--- ota_verify_hash\n");
    
    byte hash[HASHSIZE];
    ota_hash(address, signature->size, hash, file_first_byte[0]);
//     int i;
//     printf("signhash:"); for (i=0;i<HASHSIZE;i++) printf(" %02x",signature->hash[i]); printf("\n");
//     printf("calchash:"); for (i=0;i<HASHSIZE;i++) printf(" %02x",           hash[i]); printf("\n");
    
    if (memcmp(hash,signature->hash,HASHSIZE)) ota_hash(address, signature->size, hash, 0xff);
    
    return memcmp(hash,signature->hash,HASHSIZE);
}

int   ota_verify_signature(signature_t* signature) {
    UDPLGP("--- ota_verify_signature\n");
    
    int answer=0;

    wc_ecc_verify_hash(signature->sign, SIGNSIZE, signature->hash, HASHSIZE, &answer, &pubecckey);
    UDPLGP("signature valid: %d\n",answer);
        
    return answer-1;
}

void  ota_kill_file(int sector) {
    UDPLGP("--- ota_kill_file\n");

    byte zero[]={0x00};
    if (!spiflash_write(sector, zero, 1)) UDPLGP("error writing flash\n");
}

void  ota_swap_cert_sector() {
    UDPLGP("--- ota_swap_cert_sector\n");
    
    ota_kill_file(active_cert_sector);
    ota_finalize_file(backup_cert_sector);
    if (active_cert_sector==HIGHERCERTSECTOR) {
        active_cert_sector=LOWERCERTSECTOR;
        backup_cert_sector=HIGHERCERTSECTOR;
    } else {
        active_cert_sector=HIGHERCERTSECTOR;
        backup_cert_sector=LOWERCERTSECTOR;
    }
}

void  ota_write_status(char * version) {
    UDPLGP("--- ota_write_status\n");
    
    sysparam_set_string("ota_version", version);
}

int   ota_boot(void) {
    UDPLGP("--- ota_boot...");
    byte bootrom;
    rboot_get_last_boot_rom(&bootrom);
    UDPLGP("%d\n",bootrom);
    return 1-bootrom;
}

void  ota_temp_boot(void) {
    UDPLGP("--- ota_temp_boot\n");
    
    rboot_set_temp_rom(1);
    vTaskDelay(20); //allows UDPLOG to flush
    sdk_system_restart();
}

void  ota_reboot(void) {
    UDPLGP("--- ota_reboot\n");

    if (ledblinkHandle) {
        vTaskDelete(ledblinkHandle);
        gpio_enable(led, GPIO_INPUT);
        gpio_set_pullup(led, 0, 0);
    }
    vTaskDelay(20); //allows UDPLOG to flush
    sdk_system_restart();
}

int  ota_emergency(char * *ota_srvr) {
    UDPLGP("--- ota_emergency?\n");

    if (otabeta) {
        char *value;
        if (sysparam_get_string("ota_srvr", &value)== SYSPARAM_OK) *ota_srvr=value; else return 0;
        sysparam_set_string("ota_srvr","");
        sysparam_set_data("lcm_beta", NULL,0,0);
        UDPLGP("YES: backing up from http://%s\n",*ota_srvr);
        return 1;
    } else return 0;
}
