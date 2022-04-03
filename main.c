/* (c) 2018-2022 HomeAccessoryKid
 * LifeCycleManager dual app
 * use local.mk to turn it into the LCM otamain.bin app or the otaboot.bin app
 */

#include <stdlib.h>  //for UDPLGP and free
#include <stdio.h>
#include <esp/uart.h>
#include <esp8266.h>
#include <FreeRTOS.h>
#include <task.h>

#include <wifi_config.h>
#include <string.h>  //for stdcmp
#include <sysparam.h>

#include <ota.h>
#include <udplogger.h>

void ota_task(void *arg) {
    int holdoff_time=1; //32bit, in seconds
    char* user_repo=NULL;
    char* user_version=NULL;
    char* user_file=NULL;
    char*  new_version=NULL;
    char*  ota_version=NULL;
//    char*  lcm_version=NULL;
#ifndef OTABOOT    
    char*  btl_version=NULL;
#endif
    signature_t signature;
    extern int active_cert_sector;
    extern int backup_cert_sector;
    int file_size; //32bit
#ifdef OTABOOT    
    int have_private_key=0;
#endif
    int keyid,foundkey=0;
    char keyname[KEYNAMELEN];
    
    ota_init();
    
    file_size=ota_get_pubkey(active_cert_sector);
    
#ifdef OTABOOT    
    if (!ota_get_privkey()) { //have private key
        have_private_key=1;
        UDPLGP("have private key\n");
        if (ota_verify_pubkey()) {
            ota_sign(active_cert_sector,file_size, &signature, "public-1.key");//use this (old) privkey to sign the (new) pubkey
            vTaskDelete(NULL); //upload the signature out of band to github and flash the new private key to backupsector
        }
    }
#else
    btl_version=ota_get_btl_version();
#endif
    if (ota_boot()) ota_write_status("0.0.0");  //we will have to get user code from scratch if running ota_boot
    if ( !ota_load_user_app(&user_repo, &user_version, &user_file)) { //repo/file must be configured
        if (!strcmp(user_repo,HAAREPO)) user_file=HAAFILE;
#ifdef OTABOOT    
        if (ota_boot()) {
            new_version=ota_get_version(user_repo); //check if this repository exists at all
            if (!strcmp(new_version,"404")) {
                UDPLGP("%s does not exist! HALTED TILL NEXT POWERCYCLE!\n",user_repo);
                vTaskDelete(NULL);
            }
        }
#endif
        
        for (;;) { //escape from this loop by continue (try again) or break (boots into slot 0)
            UDPLGP("--- entering the loop\n");
            //UDPLGP("%d\n",sdk_system_get_time()/1000);
            //need for a protection against an electricity outage recovery storm
            vTaskDelay(holdoff_time*(1000/portTICK_PERIOD_MS));
            holdoff_time*=HOLDOFF_MULTIPLIER; holdoff_time=(holdoff_time<HOLDOFF_MAX) ? holdoff_time : HOLDOFF_MAX;
            
            //do we still have a valid internet connexion? dns resolve github... should not be private IP
            
            ota_get_pubkey(active_cert_sector); //in case the LCM update is in a cycle
            
            ota_set_verify(0); //should work even without certificates
            //if (lcm_version) free(lcm_version);
            if (ota_version) free(ota_version);
            ota_version=ota_get_version(OTAREPO);
            if (ota_get_hash(OTAREPO, ota_version, CERTFILE, &signature)) { //no certs.sector.sig exists yet on server
#ifdef OTABOOT    
                if (have_private_key) {
                    ota_sign(active_cert_sector,SECTORSIZE, &signature, CERTFILE); //reports to console
                    vTaskDelete(NULL); //upload the signature out of band to github and start again
                } else
#endif
                    continue; //loop and try again later
            }
            if (ota_verify_hash(active_cert_sector,&signature)) { //seems we need to download certificates
                if (ota_verify_signature(&signature)) { //maybe an update on the public key
                    keyid=1;
                    while (sprintf(keyname,KEYNAME,keyid) , !ota_get_hash(OTAREPO, ota_version, keyname, &signature)) {
                        if (!ota_verify_signature(&signature)) {foundkey=1; break;}
                        keyid++;
                    }
                    if (!foundkey) break; //leads to boot=0
                    //we found the head of the chain of pubkeys
                    while (--keyid) {
                        ota_get_file(OTAREPO,ota_version,keyname,backup_cert_sector);
                        if (ota_verify_hash(backup_cert_sector,&signature)) {foundkey=0; break;}
                        ota_get_pubkey(backup_cert_sector); //get one newer pubkey
                        sprintf(keyname,KEYNAME,keyid);
                        if (ota_get_hash(OTAREPO,ota_version,keyname,&signature)) {foundkey=0; break;}
                        if (ota_verify_signature(&signature)) {foundkey=0; break;}
                    }
                    if (!foundkey) break; //leads to boot=0
                }
                ota_get_file(OTAREPO,ota_version,CERTFILE,backup_cert_sector); //CERTFILE=public-1.key
                if (ota_verify_hash(backup_cert_sector,&signature)) break; //leads to boot=0
                ota_swap_cert_sector();
                ota_get_pubkey(active_cert_sector);
            } //certificates are good now
            
            if (ota_boot()) { //running the ota-boot software now
#ifdef OTABOOT    
                //take care our boot code gets a signature by loading it in boot1sector just for this purpose
                if (ota_get_hash(OTAREPO, ota_version, BOOTFILE, &signature)) { //no signature yet
                    if (have_private_key) {
                        file_size=ota_get_file(OTAREPO,ota_version,BOOTFILE,BOOT1SECTOR);
                        if (file_size<=0) continue; //try again later
                        ota_finalize_file(BOOT1SECTOR);
                        ota_sign(BOOT1SECTOR,file_size, &signature, BOOTFILE); //reports to console
                        vTaskDelete(NULL); //upload the signature out of band to github and start again
                    }
                }
                //switching over to a new repository, called LCM life-cycle-manager
                //lcm_version=ota_get_version(LCMREPO);
                //now get the latest ota main software in boot sector 1
                if (ota_get_hash(OTAREPO, ota_version, MAINFILE, &signature)) { //no signature yet
                    if (have_private_key) {
                        file_size=ota_get_file(OTAREPO,ota_version,MAINFILE,BOOT1SECTOR);
                        if (file_size<=0) continue; //try again later
                        ota_finalize_file(BOOT1SECTOR);
                        ota_sign(BOOT1SECTOR,file_size, &signature, MAINFILE); //reports to console
                        vTaskDelete(NULL); //upload the signature out of band to github and start again
                    } else {
                        continue; //loop and try again later
                    }
                } else { //we have a signature, maybe also the main file?
                    if (ota_verify_signature(&signature)) continue; //signature file is not signed by our key, ABORT
                    if (ota_verify_hash(BOOT1SECTOR,&signature)) { //not yet downloaded
                        file_size=ota_get_file(OTAREPO,ota_version,MAINFILE,BOOT1SECTOR);
                        if (file_size<=0) continue; //try again later
                        if (ota_verify_hash(BOOT1SECTOR,&signature)) continue; //download failed
                        ota_finalize_file(BOOT1SECTOR);
                    }
                } //now file is here for sure and matches hash
                //when switching to LCM we need to introduce the latest public key as used by LCM
                //ota_get_file(LCMREPO,lcm_version,CERTFILE,backup_cert_sector);
                //ota_get_pubkey(backup_cert_sector);
                //if (ota_verify_signature(&signature)) continue; //this should never happen
                ota_temp_boot(); //launches the ota software in bootsector 1
#endif
            } else {  //running ota-main software now
#ifndef OTABOOT    
                UDPLGP("--- running ota-main software\n");
                //is there a newer version of the bootloader...
                if (new_version) free(new_version);
                new_version=ota_get_version(BTLREPO);
                if (strcmp(new_version,"404")) {
                    if (ota_compare(new_version,btl_version)>0) { //can only upgrade
                        UDPLGP("BTLREPO=\'%s\' new_version=\'%s\' BTLFILE=\'%s\'\n",BTLREPO,new_version,BTLFILE);
                        if (!ota_get_hash(BTLREPO, new_version, BTLFILE, &signature)) {
                            if (!ota_verify_signature(&signature)) {
                                file_size=ota_get_file(BTLREPO,new_version,BTLFILE,backup_cert_sector);
                                if (file_size>0 && !ota_verify_hash(backup_cert_sector,&signature)) {
                                    ota_finalize_file(backup_cert_sector);
                                    ota_copy_bootloader(backup_cert_sector, file_size, new_version); //transfer it to sector zero
                                }
                            }
                        } //else maybe next time more luck for the bootloader
                    } //no bootloader update 
                }
                //if there is a newer version of ota-main...
                if (ota_compare(ota_version,OTAVERSION)>0) { //set OTAVERSION when running make and match with github
                    ota_get_hash(OTAREPO, ota_version, BOOTFILE, &signature);
                    if (ota_verify_signature(&signature)) break; //signature file is not signed by our key, ABORT
                    file_size=ota_get_file(OTAREPO,ota_version,BOOTFILE,BOOT0SECTOR);
                    if (file_size<=0) continue; //something went wrong, but now boot0 is broken so start over
                    if (ota_verify_hash(BOOT0SECTOR,&signature)) continue; //download failed
                    ota_finalize_file(BOOT0SECTOR);
                    break; //leads to boot=0 and starts self-updating/otaboot-app
                } //ota code is up to date
                ota_set_verify(1); //reject faked server only for user_repo
                if (new_version) free(new_version);
                new_version=ota_get_version(user_repo);
                if (ota_compare(new_version,user_version)>0) { //can only upgrade
                    UDPLGP("user_repo=\'%s\' new_version=\'%s\' user_file=\'%s\'\n",user_repo,new_version,user_file);
                    if (!ota_get_hash(user_repo, new_version, user_file, &signature)) {
                        file_size=ota_get_file(user_repo,new_version,user_file,BOOT0SECTOR);
                        if (file_size<=0 || ota_verify_hash(BOOT0SECTOR,&signature)) continue; //something went wrong, but now boot0 is broken so start over
                        ota_finalize_file(BOOT0SECTOR); //TODO return status and if wrong, continue
                        ota_write_status(new_version); //we have been successful, hurray!
                    } else break; //user did not supply a proper sig file or fake server -> return to boot0
                } //nothing to update
                break; //leads to boot=0 and starts updated user app
#endif
            }
        }
    }
    ota_reboot(); //boot0, either the user program or the otaboot app
    vTaskDelete(NULL); //just for completeness sake, would never get till here
}

void emergency_task(void *ota_srvr) {
    UDPLGP("--- emergency_task\n");
    signature_t signature;
    extern int active_cert_sector;
    
    ota_active_sector();
    ota_get_pubkey(active_cert_sector);
    if (ota_get_hash(ota_srvr,EMERGENCY,BOOTFILE,&signature))       vTaskDelete(NULL);
    if (ota_verify_signature(&signature))                           vTaskDelete(NULL);
    if (ota_get_file(ota_srvr,EMERGENCY,BOOTFILE,BOOT0SECTOR)<=0)   vTaskDelete(NULL);
    if (ota_verify_hash(BOOT0SECTOR,&signature))                    vTaskDelete(NULL);
    ota_finalize_file(BOOT0SECTOR);
    ota_reboot(); //boot0, the new otaboot app
    vTaskDelete(NULL); //just for completeness sake, would never get till here
}

void on_wifi_ready() {
    UDPLGP("--- on_wifi_ready\n");
    char* ota_srvr=NULL;

    if (ota_emergency(&ota_srvr)){
        xTaskCreate(emergency_task,EMERGENCY,4096,ota_srvr,1,NULL);
    } else {
        xTaskCreate(ota_task,"ota",4096,NULL,1,NULL);
    }
}

void pre_wifi_config(void *pvParameters) {
    UDPLGP("--- pre_wifi_config\n");
    ota_read_rtc(); //read RTC outcome from rboot4lcm and act accordingly
    wifi_config_init("LCM", NULL, on_wifi_ready); //expanded it with setting repo-details
    vTaskDelete(NULL);
}

void user_init(void) {
    uart_set_baud(0, 115200);
    UDPLGP("\n\n\n\n\n\n\n--- user_init\n");
#ifdef OTABOOT    
    UDPLGP("--- OTABOOT ");
#else 
    UDPLGP("--- OTAMAIN ");
#endif
    UDPLGP("VERSION: %s\n",OTAVERSION);

    xTaskCreate(udplog_send, "logsend", 1024, NULL, 2, NULL);
    xTaskCreate(pre_wifi_config, "pre_wifi", 1024, NULL, 1, NULL);
}
