/******************************************************************************
Copyright (c) 2023  Nordic Semiconductor ASA
SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************
Simple broadcast of DECT NR+ messages, for initial testing. 

2 Development Kits for 9160 needed
   1st transmits a counter value, needs only power
   2nd receives the value, needs terminal for printout

PC SW: nRF Connect for Desktop 
For development Zephyr and IDE (VSCode and nRF Connect extension)

Device first listens on channel for 10secs, if no transmission detected, 
starts sending for-ever. Another device can start, listens and stays in listen 
mode, simple statistics are provided at end, when button is pressed. Reset 
board to start again

RX accepts first received counter value, and after that detects if messages
lost between receptions, increases a counter for missed messages
- RX calculates CRC error callbacks
- RX printouts basic data for each message received the to show progress
- RX will end if nothing received in 10 secs or if any button on DK pressed
- When RX ends, simple statistics shown, success rate is 
  #received_msgs / (#received_msgs + #missed_msgs + #crc_errors)

TX Mode: leds blink
RX mode: leds on
*******************************************************************************
PRINTOUT
** Booting Zephyr OS build v3.2.99-ncs1-1547-ge2bec540218d ***
START DECT init
initialize_cb Status 0
Init done
time_query_cb time 10481690
RECEIVED DATA, 1386, rssi_2, -50,  DATA, 20314, missed/crc errors,  19
RECEIVED DATA, 1387, rssi_2, -50,  DATA, 20315, missed/crc errors,  19
...
PCC CRC ERROR, rssi_2, -52, crc error count,  7
RECEIVED DATA, 1389, rssi_2, -50,  DATA, 20318, missed/crc errors,  20
...
Exit on timeout or button
*********************************************
Success rate 0.97
Received messages 1409
Missed messages 13
CRC errors  7
RSSI_2 AVG  -52.7
*********************************************

progress line explained
RECEIVED DATA, 1389, rssi_2, -50,  DATA, 20318, missed/crc errors,  20
               ^ count of messages received
                           ^ dB
                                        ^received counter value from TX unit
****************************************************************************/

#include <string.h>
#include <zephyr/kernel.h>
#include <dk_buttons_and_leds.h>
#include <nrf_modem_dect_phy.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(app);

//state flags
// switch between RX or TX role
int RECEIVER_ROLE = 0;
int INIT_DONE = 0;
int EXIT =0;

int txHandle = 1;
int rxHandle = 31400;
// stats
int previous_received=-1;
int missing_errors=0;
int crc_errors=0;
int received_ok =0;
float rssi_average = 0;
int n=0;

//Note that the MCS impacts how much data can be fit into subslots/slots
//this is now hardcoded assuming MCS 1
#define MCS  1
// tx power, 0x0b == 19 dBm
#define POWER  0xb
#define DATA_LEN 37
uint8_t _txData[DATA_LEN];
uint8_t _rxData[4];
//defining  carrier to use
#define CARRIER 1677


union nrf_modem_dect_phy_hdr phyHeader;
struct nrf_modem_dect_phy_rssi_params rssi_scan;
//TYPE 1 (SHORT BROADCAST) FORMAT 000
struct phy_ctrl_field_common
{
    uint32_t packet_length           : 4;
    uint32_t packet_length_type      : 1;
    uint32_t header_format           : 3;
    uint32_t short_network_id        : 8;
    uint32_t transmitter_id_hi : 8;
    uint32_t transmitter_id_lo : 8;
    uint32_t df_mcs         : 3;
    uint32_t reserved       : 1;
    uint32_t transmit_power : 4;
    uint32_t pad            : 24;
};

//timer is called if there is nothing received, in received role, for 10 seconds 
void timer_expiry_function(struct k_timer *dummy)
{
    //timeout after the initial role selection means exit
    if(INIT_DONE == 1) EXIT=1;
    //timeout on initial listen, go to tx mode, init is done
    else {
      INIT_DONE =1;
      RECEIVER_ROLE = 0;
    }
}
K_TIMER_DEFINE(my_timer, timer_expiry_function, NULL);

//stop on ANY button
void button_handler(uint32_t button_state, uint32_t has_changed)
{
    EXIT=1;
}

//ETSI TS 103 636-2  spec 8.3.3 
int32_t calcRSSI(int16_t recrssi, int is_success){
  float resp =-20-((-recrssi-1)*0.5);
  //avg_new=avg_old+(value-avg_old)/n
  if(is_success) {
    n++;
    float new_average = rssi_average + (resp-rssi_average)/n;
    rssi_average = new_average;
  }
  return (int32_t)resp;
}

// Callback functions
void init( const uint64_t *time, int status,
                                  const struct nrf_modem_dect_phy_modem_cfg  *cfg)
{
  if(status==0) LOG_DBG("DECT Init done ");
  else LOG_ERR("INIT FAILED");
  
}

void op_complete(const uint64_t *time, int status,
                    uint32_t handle)
{
  LOG_DBG("operation_complete_cb Status %d Handle %d", status, handle);
  return;
}

void rx_stop(const uint64_t *time, int status,
                uint32_t handle)
{
  LOG_DBG("operation_stop_cb Status %d Handle %d", status, handle);
  return;
}

void pcc(
  const uint64_t *time,
  const struct nrf_modem_dect_phy_rx_pcc_status *status,
  const union nrf_modem_dect_phy_hdr *hdr)
{
  LOG_DBG("pcc_cb phy_header_valid %d rssi_2 %d", status->is_phy_header_valid, status->rssi_2);
  return;
}

void pcc_crc_err(const uint64_t *time, const struct nrf_modem_dect_phy_rx_pcc_crc_failure *crc_failure)
{
  crc_errors++;
  int16_t resp=calcRSSI(crc_failure->rssi_2, 0);
  LOG_INF("PCC CRC ERROR, rssi_2, %d, crc error count,  %d, continuing", resp, crc_errors);
}

void pdc(
  const uint64_t *time,
  const struct nrf_modem_dect_phy_rx_pdc_status *status,
  const void *data, uint32_t len)
{
  int rx_counter=0;
  int32_t rx_rssi=calcRSSI(status->rssi_2, 1);
  memcpy(&_rxData, data, 4);
  rx_counter = (_rxData[0]<<24) + (_rxData[1]<<16) + (_rxData[2]<<8) + (_rxData[3]);
  received_ok++;
  if(previous_received>0 && rx_counter != previous_received+1){
    //multiple errors if multiple messages lost
    missing_errors=missing_errors+(rx_counter-previous_received)-1;
  }
  previous_received=rx_counter;
  if(rx_counter%10==0) LOG_INF("RECEIVED DATA, %d, rssi_2, %d, missed/crc errors, %d", rx_counter, rx_rssi, missing_errors);
  // first listen done, somethig received, continue listen
  if(INIT_DONE==0) {
    INIT_DONE=1;
    RECEIVER_ROLE=1;
  }
  //restart the timer
  k_timer_start(&my_timer, K_SECONDS(10), K_SECONDS(10));
}

void pdc_crc_err(
  const uint64_t *time, const struct nrf_modem_dect_phy_rx_pdc_crc_failure *crc_failure)
{
  crc_errors++;
  int16_t resp=calcRSSI(crc_failure->rssi_2, 0);
  LOG_INF("PDC CRC ERROR, rssi_2, %d, crc error count, %d, continuing", resp, crc_errors);
}

void rssi(
  const uint64_t *time,
  const struct nrf_modem_dect_phy_rssi_result *status)
{
  LOG_DBG(" %d, %d, %d", status->carrier, status->unframed.high_level, status->unframed.low_level);   
  return;
}

void link_config(const uint64_t *time, int status)
{
  return;
}

void time_get(const uint64_t *time, int status)
{
  LOG_DBG("time_query_cb time %"PRIu64"", *time); 
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

void modem_rx(uint32_t rxMode, int time_s)
{
  // Setup the nrf_modem_dect_phy_operation_rx
  struct nrf_modem_dect_phy_rx_params rxOpsParams;
  rxOpsParams.start_time = 0;
  rxOpsParams.handle = rxHandle;
  rxOpsParams.mode = rxMode;
  rxOpsParams.link_id = NRF_MODEM_DECT_PHY_LINK_UNSPECIFIED;
  rxOpsParams.rssi_level = 0;
  rxOpsParams.carrier = CARRIER;
  // modem clock ticks NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ --> 69120*1000* TIME_S
  rxOpsParams.duration = time_s*69120*1000; 
  rxOpsParams.filter.short_network_id = (uint8_t)(0x0a);
  rxOpsParams.filter.is_short_network_id_used = 1;
  rxOpsParams.filter.receiver_identity = 0;
  int err=nrf_modem_dect_phy_rx(&rxOpsParams);
  if(err!=0) LOG_ERR("RX FAIL");
  if(rxHandle<65000) rxHandle=31400;
  else rxHandle++;
}

void modem_tx(uint32_t i)
{
  // with the parameters, data must be 17 bytes
  
  uint8_t tmp[DATA_LEN];
  tmp[0] = (i >> 24) & 0xff;
  tmp[1] = (i >> 16) & 0xff;
  tmp[2] = (i >> 8) & 0xff;
  tmp[3] = (i) & 0xff;
  
  for (int j=4;j<DATA_LEN;j++)
  {
    tmp[j]=0x20;
  }   
  //FIXME, length checks
  memcpy(_txData, tmp, sizeof(tmp));
  //data as TBS, FITS TO 1
  struct phy_ctrl_field_common header = {
      //short header format, broadcast
      .header_format = (uint8_t)0x0,
      //length given in subslots
      .packet_length_type =  (uint8_t)0x0,
      //lenght in type
      .packet_length = (uint8_t) 0x01,
      .short_network_id = (uint8_t)(0x0a & 0xff),
      .transmitter_id_hi = (uint8_t) (0x0101 >> 8),
      .transmitter_id_lo = (uint8_t) (0x0101 & 0xff),
      // note that on the HW the maximum seems to be +19dB
      .transmit_power = POWER,
      .reserved = 0,
      //lowest MCS, maximum range aimed
      .df_mcs = MCS
  };
  memcpy(&phyHeader.type_1, &header, 5);

  // Setup the nrf_modem_dect_phy_operation_tx
  struct nrf_modem_dect_phy_tx_params txOpsParams;
  //immediate operation
  txOpsParams.start_time = 0; 
  txOpsParams.handle = txHandle;
  txOpsParams.network_id = 0x0a;
  txOpsParams.phy_type = 0;
  txOpsParams.lbt_rssi_threshold_max = 0;
  //  EU carrier, see ETSI TS 103 636-2 5.4.2 for the calculation 
  txOpsParams.carrier = CARRIER;
  //no LBT done
  txOpsParams.lbt_period = 0;
  txOpsParams.phy_header = &phyHeader;
  txOpsParams.data = _txData;
  txOpsParams.data_size = sizeof(tmp);

  // and call nrf_modem_dect_phy_schedule_tx_operation_add()
  int e=nrf_modem_dect_phy_tx(&txOpsParams);
  if(e!=0) LOG_ERR("TX FAIL");
  if(txHandle>30000) txHandle=1;
  else txHandle++;
}


void main(void)
  {
  //send an increasing counter, start from 1 
  uint32_t i =1;
  LOG_INF("START DECT");
  nrf_modem_dect_phy_init(&dect_cb_config);
  dk_buttons_init(button_handler);
  dk_leds_init();
  k_msleep(1000);
  
  LOG_INF("Listening on channel %d for 10 secs to see if there is transmissions", CARRIER);
  k_timer_start(&my_timer, K_SECONDS(10), K_SECONDS(10));
  modem_rx(NRF_MODEM_DECT_PHY_RX_MODE_SINGLE_SHOT, 10);
  
  //wait for initial listen, what role to take
  while(INIT_DONE==0) k_msleep(1000);

  //TX ROLE, LOOP
  if(RECEIVER_ROLE==0) {
    dk_set_led_on(1);
    LOG_INF("TX ROLE");
    while(1) {
      k_msleep(330);
      if(i%2==0) {
        dk_set_led_on(DK_LED1);
        dk_set_led_on(DK_LED2);
      }
      else {
        dk_set_led_off(DK_LED1);
        dk_set_led_off(DK_LED2);
      }
      modem_tx(i);
      if(i%10==0) LOG_INF("TX %d",i);
      i++;
      if(i==INT32_MAX) {
        i=0;
        LOG_INF("Sent integer value looped");
      }
    }
  }
  // RX ROLE, LOOP
  if(RECEIVER_ROLE==1) {
    dk_set_led_on(DK_LED1);
    dk_set_led_on(DK_LED2);
    LOG_INF("RX ROLE");
    //timer is used, if there is 10 seconds without any reception, exits
    //timer is refreshed/restarted in reception
    k_timer_start(&my_timer, K_SECONDS(10), K_SECONDS(10));
    //loop until above timer sets the EXIT flag when nothing received in 10 secs
    while(EXIT==0){
      //really agressice checking of the RX mode is still active   
      modem_rx(NRF_MODEM_DECT_PHY_RX_MODE_SINGLE_SHOT, 2);
      k_msleep(1);
    }
    //messages may be in logging pipeline, wait a sec
    k_msleep(1000);
    LOG_INF("Exit on timeout or button"); 
    LOG_INF("*********************************************");
    //CRC error causes a missed message, so missing errors includes also CRC
    LOG_INF("Received messages %d", received_ok); 
    LOG_INF("Missed messages %d", (missing_errors-crc_errors)); 
    LOG_INF("CRC errors  %d", crc_errors); 
    //no float in vanilla print_k, need to config 
    LOG_INF("RSSI_2 AVG  (rounded) %d", (int)rssi_average); 
    LOG_INF("*********************************************");
  }

}