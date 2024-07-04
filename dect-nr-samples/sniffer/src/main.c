/******************************************************************************
Copyright (c) 2023  Nordic Semiconductor ASA
SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************
Simple sniffer, prints out messages seen 
****************************************************************************
TODO:
- 
****************************************************************************/

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <dk_buttons_and_leds.h>
#include <nrf_modem_dect_phy.h>
#include <modem/nrf_modem_lib.h>


LOG_MODULE_REGISTER(app);

//state flags
//switch between RX or TX role
int RECEIVER_ROLE = 1;
int INIT_DONE = 0;
int EXIT =0;

//handle values for API calls, separate tx and rx
int txHandle = 1;
int rxHandle = 31400;
// statistics collecting
int previous_received=-1;
int missing_errors=0;
int crc_errors=0;
int received_ok =0;
float rssi_average = 0;
int n=0;

//Note that the MCS impacts how much data can be fit into subslots/slots
#define MCS  1
// tx power, 0x0d == 19 dBm, maximum of the HW
#define POWER  0x0d
//this depends on the MCS above
#define DATA_LEN 137
//MCS 4, 4 subslots
//#define DATA_LEN 407
#define PACKET_LEN 4 //subslots
uint8_t _txData[DATA_LEN];
uint8_t _rxData[DATA_LEN];
//NOTE !!! defining  carrier to use, please modify according to region and scan results
#define CARRIER 1677

//semaphore for API calls, only 1 async operation at time in this sample 
K_SEM_DEFINE(modem, 1, 1);

//TYPE 1 (SHORT BROADCAST) FORMAT 000 header for messages used
struct phy_ctrl_field_common
{
    uint8_t packet_length           : 4;
    uint8_t packet_length_type      : 1;
    uint8_t header_format           : 3;
    uint8_t short_network_id;
    uint8_t transmitter_id_hi;
    uint8_t transmitter_id_lo;
    uint8_t df_mcs         : 3;
    uint8_t reserved       : 1;
    uint8_t transmit_power : 4;
};
union nrf_modem_dect_phy_hdr phyHeader;

//new parameters for HARQ operation, not used in this sample
const struct nrf_modem_dect_phy_init_params init_params ={
	.harq_rx_expiry_time_us=5000000,
	.harq_rx_process_count=1
};


//exit on ANY button on the devkit
void button_handler(uint32_t button_state, uint32_t has_changed)
{
    EXIT=1;
}


// Callback functions from PHY API
void init(const uint64_t *time, int16_t temp, enum nrf_modem_dect_phy_err err, const struct nrf_modem_dect_phy_modem_cfg *cfg)
{
  if(err==0) {
    LOG_INF("DECT Init done, temperature %d", temp);
  }
  else {
    LOG_ERR("INIT FAILED");
    printk("Init failed, Exit\n");
    EXIT=1;
  }
  k_sem_give(&modem);
}

void op_complete(const uint64_t *time, int16_t temperature, enum nrf_modem_dect_phy_err err, uint32_t handle)
{
  LOG_DBG("operation_complete_cb Status %d, Temp %d, Handle %d", err, temperature, handle);
  k_sem_give(&modem);
  return;
}

void rssi(const uint64_t *time, const struct nrf_modem_dect_phy_rssi_meas *status)
{   
  k_sem_give(&modem);
  return;
}


void rx_stop(const uint64_t *time, enum nrf_modem_dect_phy_err err, uint32_t handle)
{
  LOG_DBG("operation_stop_cb Status %d Handle %d", err, handle);
  k_sem_give(&modem);
  return;
}

//phy header receive
void pcc(
  const uint64_t *time,
  const struct nrf_modem_dect_phy_rx_pcc_status *status,
  const union nrf_modem_dect_phy_hdr *hdr)
{
  int16_t resp=status->rssi_2 / 2;
  LOG_INF("pcc_cb phy_header_valid %d rssi_2 %d", status->header_status, resp);
  LOG_HEXDUMP_INF(hdr, sizeof(*hdr), "\tRX PCC: ");
  return;
}

void pcc_crc_err(const uint64_t *time, const struct nrf_modem_dect_phy_rx_pcc_crc_failure *crc_failure)
{
  LOG_DBG("PCC CRC ERROR, rssi_2, %d", crc_failure->rssi_2/2);
}

//data paylod receive, statistics calculation and tracking previous received message number
void pdc(
  const uint64_t *time,
  const struct nrf_modem_dect_phy_rx_pdc_status *status,
  const void *data, uint32_t len)
{
 
  LOG_INF("PDC DATA, LEN %d, rssi_2 %d, SNR %d", len, status->rssi_2/2, status->snr);
  LOG_HEXDUMP_INF(data, len, "\tRX PDC: ");

}

void pdc_crc_err(
  const uint64_t *time, const struct nrf_modem_dect_phy_rx_pdc_crc_failure *pdc_failure)
{
  crc_errors++;
  LOG_DBG("PDC CRC ERROR, rssi_2, %d", pdc_failure->rssi_2/2);
}

void link_config(const uint64_t *time, enum nrf_modem_dect_phy_err err)
{
  return;
}

void time_get(const uint64_t *time, enum nrf_modem_dect_phy_err err)
{
  LOG_DBG("Time query response time %"PRIu64" Status %d", *time, err); 
}

void capability_get(const uint64_t *time, enum nrf_modem_dect_phy_err err,const struct nrf_modem_dect_phy_capability *capability)
{
  LOG_DBG("Capability query response FIXME %"PRIu64" Status %d", *time, err); 
}

void deinit(const uint64_t *time, enum nrf_modem_dect_phy_err err)
{
  LOG_DBG("DEINIT response time %"PRIu64" Status %d", *time, err); 
}

//set function callbacks to structure, registered to  modem API  in main
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

//listen, start immediately and listen for time_s duration
void modem_rx(uint32_t rxMode, int time_s)
{
  // Setup the nrf_modem_dect_phy_operation_rx
  struct nrf_modem_dect_phy_rx_params rxOpsParams={0};
  rxOpsParams.start_time = 0; //start immediately
  rxOpsParams.handle = rxHandle;
  rxOpsParams.network_id=0;
  rxOpsParams.mode = rxMode;
  rxOpsParams.link_id = NRF_MODEM_DECT_PHY_LINK_UNSPECIFIED;
  rxOpsParams.rssi_level = -60;
  rxOpsParams.carrier = CARRIER;
  // modem clock ticks NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ --> 69120*1000* TIME_S
  rxOpsParams.duration = time_s*69120*1000; 
  //filter on the short network id, last 8 bits of the network identifier in dect nr
  rxOpsParams.filter.short_network_id = (uint8_t)(0x0a);
  rxOpsParams.filter.is_short_network_id_used = 0;
  //listen for everything (broadcast mode usedd)
  rxOpsParams.filter.receiver_identity = 0;
  k_sem_take(&modem, K_FOREVER);
  int err=nrf_modem_dect_phy_rx(&rxOpsParams);
  if(err!=0) LOG_ERR("RX FAIL %d", err);
  if(rxHandle==65000)rxHandle=31400;
  else rxHandle++;
}


int main(void)
  {
  k_msleep(100);
  //send an increasing counter, start from 1 

  //using printk, will show something even if logging filtering is not set correctly
  printk("START DECT SAMPLE\n");
  dk_buttons_init(button_handler);
  printk("Buttons init\t");
  dk_leds_init();
  printk("leds init\t");
  
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
  printk("DECT init started\n");
  
  printk("Listening on channel %d for transmissions\n", CARRIER);
  
  // RX ROLE, LOOP
  dk_set_led_on(DK_LED1);
  dk_set_led_on(DK_LED2);
  printk("RX ROLE\n");

  while(EXIT==0){
    //loop RX mode   
    modem_rx(NRF_MODEM_DECT_PHY_RX_MODE_CONTINUOUS, 2);
  }
  //messages may be in logging pipeline, wait a sec
  k_msleep(1000);
  printk("\nEXIT Listening\n");
  return 0;
}