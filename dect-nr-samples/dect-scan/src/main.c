/******************************************************************************
Copyright (c) 2023  Nordic Semiconductor ASA
SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************
Simple scan of DECT NR+ channels
******************************************************************************/

#include <string.h>
#include <zephyr/kernel.h>
#include <dk_buttons_and_leds.h>
#include <nrf_modem_dect_phy.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(APP);

#define START_CHAN 1657
#define END_CHAN 1677
// scan for carreir that has lowest in-use dbm
int min_carrier=0;
int min_rssi=0;
uint64_t modem_base_time=0;
int handle=0;

int EXIT=0;
int INIT_DONE=0;

K_SEM_DEFINE(modem, 1, 1);
struct nrf_modem_dect_phy_rssi_params rssi_scan;


// Callback functions
void init( const uint64_t *time, int status,
                                  const struct nrf_modem_dect_phy_modem_cfg  *cfg)
{
  if(status==0) {
    LOG_INF("Init done");
  }
  else {
    LOG_ERR("INIT FAILED");
  }
  k_sem_give(&modem);
}

void op_complete(const uint64_t *time, int status,
                    uint32_t handle)
{
  if(status!=0)LOG_ERR("OP COMPLETE %d status %d", handle, status);
  else LOG_DBG("OP COMPLETE %d status OK", handle, status); 
  k_sem_give(&modem);
}

void rx_stop(const uint64_t *time, int status,
                uint32_t handle)
{
  LOG_DBG("RX STOP");
}

void pcc(
  const uint64_t *time,
  const struct nrf_modem_dect_phy_rx_pcc_status *status,
  const union nrf_modem_dect_phy_hdr *hdr)
{
  LOG_DBG("PCC");
}

void pcc_crc_err(const uint64_t *time, const struct nrf_modem_dect_phy_rx_pcc_crc_failure *crc_failure)
{
  LOG_DBG("PCC CRC ERROR");
}

void pdc(
  const uint64_t *time,
  const struct nrf_modem_dect_phy_rx_pdc_status *status,
  const void *data, uint32_t len)
{
  LOG_DBG("PDC");
}

void pdc_crc_err(
  const uint64_t *time, const struct nrf_modem_dect_phy_rx_pdc_crc_failure *crc_failure)
{
  LOG_DBG("PDC CRC ERROR");
}

void rssi(
  const uint64_t *time,
  const struct nrf_modem_dect_phy_rssi_result *status)
{

  if(status->mode==NRF_MODEM_DECT_PHY_RSSI_MODE_UNFRAMED){
    LOG_INF(" Carrier %d, high %d, low %d", status->carrier, status->unframed.high_level, status->unframed.low_level);   
    if (status->unframed.high_level<min_rssi){
      min_carrier=status->carrier;
      min_rssi=status->unframed.high_level;
      LOG_DBG("updated min_carrier");
    }
  }
  else if(status->mode==NRF_MODEM_DECT_PHY_RSSI_MODE_FRAMED_UNPACKED){
    LOG_INF(" Carrier %d", status->carrier);
    for(int i=1; i<25;i++){
      int8_t slot_vals[10];
      for(int j=0; j<10;j++){
        slot_vals[j]=status->framed_unpacked->values[(i*j)];
      }
      LOG_INF("Slot %d \tsymbols: %d %d %d %d %d %d %d %d %d %d", i, slot_vals[0],
            slot_vals[1],
            slot_vals[2],
            slot_vals[3],
            slot_vals[4],
            slot_vals[5],
            slot_vals[6],
            slot_vals[7],
            slot_vals[8],
            slot_vals[9]);
    
    }   
    
  }

}

void link_config(const uint64_t *time, int status)
{
  return;
}

void time_get(const uint64_t *time, int status)
{
  LOG_DBG("time_query_cb time %"PRIu64"", *time); 
  modem_base_time=*time;
  k_sem_give(&modem);
}

struct nrf_modem_dect_phy_init_params dect_cb_config = {
  .callbacks ={
    .init = init,
    .op_complete = op_complete,
    .rx_stop = rx_stop,
    .pcc = pcc,
    .pcc_crc_err = pcc_crc_err,
    .pdc = pdc,
    .pdc_crc_err = pdc_crc_err,
    .rssi = rssi,
    .link_config = link_config,
    .time_get = time_get
  }
};

//scan operation
void modem_scan(int simple){
  LOG_INF("RSSI SCAN Started");
  // scannin channels, note that channels are every 0.864MHz, so jumping 2 for 1.7MHz bandwidth
  for(int i=START_CHAN;i<=END_CHAN;i=i+2){
    rssi_scan.start_time=0;
    rssi_scan.handle=handle;
    rssi_scan.carrier=i;
    //KHZ *1000 == HZ is per second / 100 == 10ms frames
    if(simple==1) {
      LOG_DBG("Simple scan %d",i);
      rssi_scan.duration=NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ*10;
      rssi_scan.mode=NRF_MODEM_DECT_PHY_RSSI_MODE_UNFRAMED;
    }
    else{
      LOG_DBG("FRAMED_UNPACKED scan %d",i);
      //for frame_unpacked mode max 10ms
      rssi_scan.duration=NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ*10;
      rssi_scan.mode=NRF_MODEM_DECT_PHY_RSSI_MODE_FRAMED_UNPACKED;
      //base time should be a framestart, now some value
      rssi_scan.framed_unpacked.base_time=modem_base_time;
    }

    k_sem_take(&modem, K_FOREVER);
    int e=nrf_modem_dect_phy_rssi(&rssi_scan);
    if(e!=0) LOG_ERR("RSSI FAIL");
    else LOG_DBG("RSSI request made %d", handle);
    handle++;

  }
  LOG_DBG("Scan loop done");
}


void main(void)
{
  LOG_INF("START DECT INIT"); 
  k_sem_take(&modem, K_FOREVER);
  nrf_modem_dect_phy_init(&dect_cb_config);
  LOG_INF("Simple Scan");
  modem_scan(1);
  
  LOG_INF("FRAME_UNPACKED Scan");
  k_sem_take(&modem, K_FOREVER);
  nrf_modem_dect_phy_time_get();
  while(modem_base_time==0) k_msleep(10);
  modem_scan(0);

  //wait for last results
  k_sem_take(&modem, K_FOREVER);
  LOG_INF("Exit");
}
