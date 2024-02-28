/******************************************************************************
Copyright (c) 2023  Nordic Semiconductor ASA
SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************
Simple scan of DECT NR+ channels
******************************************************************************/

#include <string.h>
#include <zephyr/kernel.h>
#include <dk_buttons_and_leds.h>
#include <modem/nrf_modem_lib.h>
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

K_SEM_DEFINE(modem, 1, 1);
struct nrf_modem_dect_phy_rssi_params rssi_scan;

//new parameters for HARQ operation, not used in this sample
const struct nrf_modem_dect_phy_init_params init_params ={
	.harq_rx_expiry_time_us=5000000,
	.harq_rx_process_count=1
};

// Callback functions
void init(const uint64_t *time, int16_t temp, enum nrf_modem_dect_phy_err err, const struct nrf_modem_dect_phy_modem_cfg *cfg)
{
  if(err==0) {
    printk("DECT Init done, temperature %d\n", temp);
  }
  else {
    printk("INIT FAILED\n");
  }
  k_sem_give(&modem);
}

void op_complete(const uint64_t *time, int16_t temperature, enum nrf_modem_dect_phy_err err, uint32_t handle)
{
  k_sem_give(&modem);
  return;
}


void rx_stop(const uint64_t *time, enum nrf_modem_dect_phy_err err, uint32_t handle)
{
  return;
}

void pcc(
  const uint64_t *time,
  const struct nrf_modem_dect_phy_rx_pcc_status *status,
  const union nrf_modem_dect_phy_hdr *hdr)
{
  return;
}

void pcc_crc_err(const uint64_t *time, const struct nrf_modem_dect_phy_rx_pcc_crc_failure *crc_failure)
{
  return;  
}

//data paylod receive, statistics calculation and tracking previous received message number
void pdc(
  const uint64_t *time,
  const struct nrf_modem_dect_phy_rx_pdc_status *status,
  const void *data, uint32_t len)
{
  return;
}

void pdc_crc_err(
  const uint64_t *time, const struct nrf_modem_dect_phy_rx_pdc_crc_failure *crc_failure)
{
  return;
}

void link_config(const uint64_t *time, enum nrf_modem_dect_phy_err err)
{
  return;
}

void time_get(const uint64_t *time, enum nrf_modem_dect_phy_err err)
{
  return; 
}

void capability_get(const uint64_t *time, enum nrf_modem_dect_phy_err err,const struct nrf_modem_dect_phy_capability *capability)
{
  return; 
}

void deinit(const uint64_t *time, enum nrf_modem_dect_phy_err err)
{
  return; 
}

void rssi(const uint64_t *time, const struct nrf_modem_dect_phy_rssi_meas *meas)
{
  printk("\nCarrier, %d ", meas->carrier);
  printk("Measurements %d, ", meas->meas_len);
  bool saturated=false;
  bool not_meas=false;
  int min=0;
  int max=-100;
  for(int i=0; i<meas->meas_len;i++){
    int m=meas->meas[i];
    if(m>0) saturated=true;
    if(m==0) not_meas=true;
    if(m<0 && m>max) max=m;
    if(m<min) min=m;
    printk(" %d,", meas->meas[i]);
  }
  printk("\n MIN %d MAX %d\n", min, max);
  if(saturated) printk("Saturated values on carrier %d\n", meas->carrier);
  if(not_meas) printk("Not measured on carrier %d\n", meas->carrier);
}

struct nrf_modem_dect_phy_callbacks dect_cb_config = {
    .init = init,
    .op_complete = op_complete,
    .rssi = rssi,
    .rx_stop = rx_stop,
    .pcc = pcc,
    .pcc_crc_err = pcc_crc_err,
    .pdc = pdc,
    .pdc_crc_err = pdc_crc_err,
    .link_config = link_config,
    .time_get = time_get,
    .capability_get = capability_get,
    .deinit=deinit
};

//scan operation
void modem_scan(){
  printk("RSSI SCAN Started\n");
  // scannin channels, note that channels are every 0.864MHz, so jumping 2 for 1.7MHz bandwidth
  for(int i=START_CHAN;i<=END_CHAN;i=i+2){
    rssi_scan.start_time=0;
    rssi_scan.handle=handle;
    rssi_scan.carrier=i;
    //subslots
    rssi_scan.duration=96;
    rssi_scan.reporting_interval=NRF_MODEM_DECT_PHY_RSSI_INTERVAL_24_SLOTS;
    k_sem_take(&modem, K_FOREVER);
    int e=nrf_modem_dect_phy_rssi(&rssi_scan);
    if(e!=0) LOG_ERR("RSSI FAIL");
    else LOG_DBG("RSSI request made %d", handle);
    handle++;
    k_msleep(20);
  }
  k_msleep(100);
  printk("\nScan loop done\n");
}


int main(void)
{
  printk("START DECT INIT\n"); 
  nrf_modem_lib_init();
  
  k_sem_take(&modem, K_FOREVER);
  int err=0;
  err=nrf_modem_dect_phy_callback_set(&dect_cb_config);
  if(err!=0) {
    printk("ERROR settings callbacks %d\n",err);
  }
  err=nrf_modem_dect_phy_init(&init_params);
  if(err!=0) {
    printk("ERROR initializing modem PHY %d\n",err);
    return -1;
  }
  printk("DECT init done\n");
  
  modem_scan();

  //wait for last results
  k_msleep(100);
  printk("Exit\n");
  return 0;
}
