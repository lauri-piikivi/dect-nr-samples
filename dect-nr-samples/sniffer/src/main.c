/******************************************************************************
Copyright (c) 2023  Nordic Semiconductor ASA
SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************
Simple sniffer, prints out messages seen on the air DECT-2020

CONFIGURATION read from serial line, prints "Waiting configuration" and then reads
6 bytes, 4byte networkid and 2byte channel. The newtork ID is needed to descramble 
messages. 

OPERATION
Pritns DECT messages to serial.  
  Type_1 (dect nr+ beacon header) 5 bytes + fileld with  0x00 to make 10 byte header
  Type_2 (dect nr+ unicast) 10 byte header
  PCC error is H0000

Prepends strings with P == PDC header 
  PDC error is P0000
  op_complete prints plain P for cases where only header (ACK) is received (MCS 0,
   len == 0)

NEEDS PC SW
PC python script writes configuration. Script strips the H and P identifiers, and 
sends the PCC+PDC as UDP payload to wireshark or similar.
****************************************************************************
TODO:
- accept network ID from serial line
****************************************************************************/

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <nrf_modem_dect_phy.h>
#include <modem/nrf_modem_lib.h>
#include <zephyr/drivers/uart.h>

LOG_MODULE_REGISTER(app);

// Note that the MCS impacts how much data can be fit into subslots/slots
#define MCS 1
#define WORKQ_PRIO 5
#define WORKQ_STACK_SIZE 2048
#define MAX_WORKER_BUFS 10
#define MAX_PACKET_LEN 600
// handle values for API calls, separate tx and rx
int rxHandle = 31400;
int EXIT = 0;
struct worker_buf {
  struct k_work work;
  bool is_pcc;
  bool flush;
  size_t len;
  uint8_t rx_bytes[MAX_PACKET_LEN]; 
};
//for serial printing
uint8_t pdc_data[2*MAX_PACKET_LEN] = {0}; 
uint16_t CARRIER=1663;
uint32_t NETWORK_ID=0;

#define UART_DEVICE DT_NODELABEL(uart0)  
const struct device *uart_dev = DEVICE_DT_GET(UART_DEVICE);

// semaphore for API calls, only 1 async operation at time in this sample
K_SEM_DEFINE(operation_sem, 1, 1);
K_SEM_DEFINE(serial_sem, 1, 1);
K_SEM_DEFINE(mem_sem, 1,1);
K_THREAD_STACK_DEFINE(work_queue_stack, WORKQ_STACK_SIZE);
struct k_work_q work_q;
struct worker_buf worker_buf_pool[MAX_WORKER_BUFS];
K_MSGQ_DEFINE(worker_buf_q, sizeof(struct worker_buf *), MAX_WORKER_BUFS, 4);

static struct nrf_modem_dect_phy_config_params dect_phy_config_params = {
    .band_group_index = 0,
    .harq_rx_process_count = 4,
    .harq_rx_expiry_time_us = 5000000};

void work_handler(struct k_work *work)
{
  k_sem_take(&serial_sem, K_FOREVER);
  struct worker_buf *buf = CONTAINER_OF(work, struct worker_buf, work);
  if (buf->is_pcc==true)
  { 
    pdc_data[0] = 'H';
    for (int i = 0; i < 10; i++)
    {
      sprintf(&pdc_data[1+(i*2)], "%02X", buf->rx_bytes[i]);
    }
  }
  if(buf->is_pcc==false && buf->flush==false)
  {
    pdc_data[0] = 'P';
    for (int i = 0; i <= buf->len; i++)
    {
      sprintf(&pdc_data[1+(i*2)], "%02X", buf->rx_bytes[i]);
    }   
  }
  if(buf->flush == true) {
    pdc_data[0] = 'P';
  }
  printk("%s\n", pdc_data);
  memset(pdc_data, 0, sizeof(pdc_data));
  k_sem_give(&serial_sem);
  buf->len = 0;
  buf->flush = false;
  buf->is_pcc = false;
  memset(buf->rx_bytes, 0, sizeof(buf->rx_bytes));
  k_msgq_put(&worker_buf_q, &buf, K_NO_WAIT);
  
}


/* Callback after init operation. */
static void on_init(const struct nrf_modem_dect_phy_init_event *evt)
{
  if (evt->err)
  {
    printk("ERROR Init failed, err %d\n", evt->err);
    EXIT = true;
    return;
  }

  k_sem_give(&operation_sem);
}

/* Callback after deinit operation. */
static void on_deinit(const struct nrf_modem_dect_phy_deinit_event *evt)
{
  if (evt->err)
  {
    printk("ERROR Deinit failed, err %d\n", evt->err);
    return;
  }

  k_sem_give(&operation_sem);
}

static void on_activate(const struct nrf_modem_dect_phy_activate_event *evt)
{
  if (evt->err)
  {
    printk("ERROR Activate failed, err %d\n", evt->err);
    EXIT = true;
    return;
  }

  k_sem_give(&operation_sem);
}

static void on_deactivate(const struct nrf_modem_dect_phy_deactivate_event *evt)
{

  if (evt->err)
  {
    printk("ERROR Deactivate failed, err %d\n", evt->err);
    return;
  }

  k_sem_give(&operation_sem);
}

static void on_configure(const struct nrf_modem_dect_phy_configure_event *evt)
{
  if (evt->err)
  {
    printk("ERROR Configure failed callback err %d\n", evt->err);
    return;
  }

  k_sem_give(&operation_sem);
}

/* Callback after link configuration operation. */
static void on_link_config(const struct nrf_modem_dect_phy_link_config_event *evt)
{
  return;
}

static void on_radio_config(const struct nrf_modem_dect_phy_radio_config_event *evt)
{
  if (evt->err)
  {
    printk("ERROR Radio config failed, err %d\n", evt->err);
    return;
  }

  k_sem_give(&operation_sem);
}

/* Callback after capability get operation. */
static void on_capability_get(const struct nrf_modem_dect_phy_capability_get_event *evt)
{
  return;
}

static void on_bands_get(const struct nrf_modem_dect_phy_band_get_event *evt)
{
  return;
}

static void on_latency_info_get(const struct nrf_modem_dect_phy_latency_info_event *evt)
{
  return;
}

/* Callback after time query operation. */
static void on_time_get(const struct nrf_modem_dect_phy_time_get_event *evt)
{
  return;
}

static void on_cancel(const struct nrf_modem_dect_phy_cancel_event *evt)
{

  k_sem_give(&operation_sem);
  return;
}

/* Operation complete notification. 

MCS 0, length 0 has no PDC, so we may receive just PCC header. 
*/
static void on_op_complete(const struct nrf_modem_dect_phy_op_complete_event *evt)
{
  if(evt->err!=0){
    printk("ERROR OP_COMPLETE %d\n", evt->err);
  }
  k_sem_give(&operation_sem);
  struct worker_buf *w;
  if (k_msgq_get(&worker_buf_q, &w, K_NO_WAIT) == 0) {
      w->flush = true;
      w->len = 0;
      k_work_init(&w->work, work_handler);
      k_work_submit_to_queue(&work_q, &w->work);
  }
  return;
}

/* Physical Control Channel reception notification. */
static void on_pcc(const struct nrf_modem_dect_phy_pcc_event *evt)
{
  struct worker_buf *w;
  if (k_msgq_get(&worker_buf_q, &w, K_NO_WAIT) == 0) {
    if (evt->phy_type == 0)
    {
      memset(w->rx_bytes, 0, 10);
      memcpy(w->rx_bytes, evt->hdr.type_1, 5);
    }
   else 
    {
      memcpy(w->rx_bytes, evt->hdr.type_2, 10);
    }
    w->len = 10;
    w->is_pcc = true;
    k_work_init(&w->work, work_handler);
    k_work_submit_to_queue(&work_q, &w->work);
  }
  return;
}

/* Physical Control Channel CRC error notification. */
static void on_pcc_crc_err(const struct nrf_modem_dect_phy_pcc_crc_failure_event *evt)
{
  printk("H%20X\n", 0x00);
}

/* Physical Data Channel reception notification. */
static void on_pdc(const struct nrf_modem_dect_phy_pdc_event *evt)
{
  struct worker_buf *w;
  if (k_msgq_get(&worker_buf_q, &w, K_NO_WAIT) == 0) {
    memcpy(w->rx_bytes, evt->data, (evt->len<sizeof(w->rx_bytes))?evt->len:sizeof(w->rx_bytes)); 
    w->len = evt->len<sizeof(w->rx_bytes)?evt->len:sizeof(w->rx_bytes);
    w->is_pcc = false;
    k_work_init(&w->work, work_handler);
  	k_work_submit_to_queue(&work_q, &w->work);
  }
  return;
}

/* Physical Data Channel CRC error notification. */
static void on_pdc_crc_err(const struct nrf_modem_dect_phy_pdc_crc_failure_event *evt)
{
  printk("P%20X\n", 0x00);
  return;
}

/* RSSI measurement result notification. */
static void on_rssi(const struct nrf_modem_dect_phy_rssi_event *evt)
{
  return;
}

static void on_stf_cover_seq_control(const struct nrf_modem_dect_phy_stf_control_event *evt)
{
  return;
}

static void dect_phy_event_handler(const struct nrf_modem_dect_phy_event *evt)
{

  switch (evt->id)
  {
  case NRF_MODEM_DECT_PHY_EVT_PCC:
    on_pcc(&evt->pcc);
    break;
  case NRF_MODEM_DECT_PHY_EVT_PDC:
    on_pdc(&evt->pdc);
    break;
  case NRF_MODEM_DECT_PHY_EVT_PCC_ERROR:
    on_pcc_crc_err(&evt->pcc_crc_err);
    break;
  case NRF_MODEM_DECT_PHY_EVT_PDC_ERROR:
    on_pdc_crc_err(&evt->pdc_crc_err);
    break;
  case NRF_MODEM_DECT_PHY_EVT_INIT:
    on_init(&evt->init);
    break;
  case NRF_MODEM_DECT_PHY_EVT_DEINIT:
    on_deinit(&evt->deinit);
    break;
  case NRF_MODEM_DECT_PHY_EVT_ACTIVATE:
    on_activate(&evt->activate);
    break;
  case NRF_MODEM_DECT_PHY_EVT_DEACTIVATE:
    on_deactivate(&evt->deactivate);
    break;
  case NRF_MODEM_DECT_PHY_EVT_CONFIGURE:
    on_configure(&evt->configure);
    break;
  case NRF_MODEM_DECT_PHY_EVT_RADIO_CONFIG:
    on_radio_config(&evt->radio_config);
    break;
  case NRF_MODEM_DECT_PHY_EVT_COMPLETED:
    on_op_complete(&evt->op_complete);
    break;
  case NRF_MODEM_DECT_PHY_EVT_CANCELED:
    on_cancel(&evt->cancel);
    break;
  case NRF_MODEM_DECT_PHY_EVT_RSSI:
    on_rssi(&evt->rssi);
    break;
  case NRF_MODEM_DECT_PHY_EVT_TIME:
    on_time_get(&evt->time_get);
    break;
  case NRF_MODEM_DECT_PHY_EVT_CAPABILITY:
    on_capability_get(&evt->capability_get);
    break;
  case NRF_MODEM_DECT_PHY_EVT_BANDS:
    on_bands_get(&evt->band_get);
    break;
  case NRF_MODEM_DECT_PHY_EVT_LATENCY:
    on_latency_info_get(&evt->latency_get);
    break;
  case NRF_MODEM_DECT_PHY_EVT_LINK_CONFIG:
    on_link_config(&evt->link_config);
    break;
  case NRF_MODEM_DECT_PHY_EVT_STF_CONFIG:
    on_stf_cover_seq_control(&evt->stf_cover_seq_control);
    break;
  }
}

// listen, start immediately and listen for time_s duration
void modem_rx(uint32_t rxMode, int time_s)
{
  // Setup the nrf_modem_dect_phy_operation_rx
  struct nrf_modem_dect_phy_rx_params rxOpsParams = {0};
  rxOpsParams.start_time = 0; // start immediately
  rxOpsParams.handle = rxHandle;
  rxOpsParams.network_id = NETWORK_ID;
  rxOpsParams.mode = rxMode;
  rxOpsParams.rssi_interval = NRF_MODEM_DECT_PHY_RSSI_INTERVAL_OFF;
  rxOpsParams.link_id = NRF_MODEM_DECT_PHY_LINK_UNSPECIFIED;
  rxOpsParams.rssi_level = 0;
  rxOpsParams.carrier = CARRIER;
  // modem clock ticks NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ --> 69120*1000* TIME_S
  rxOpsParams.duration = time_s * 69120 * 1000;
  // filter on the short network id, last 8 bits of the network identifier in dect nr
  rxOpsParams.filter.short_network_id = (uint8_t)(NETWORK_ID);
  rxOpsParams.filter.is_short_network_id_used = 1;
  // listen for everything 
  rxOpsParams.filter.receiver_identity = 0;
  k_sem_take(&operation_sem, K_FOREVER);
  int err = nrf_modem_dect_phy_rx(&rxOpsParams);
  if (err != 0)
    printk("RX FAIL %d\n", err);
  if (rxHandle == 65000)
    rxHandle = 31400;
  else
    rxHandle++;
}

void read_serial()
{
  uint8_t buf[6];
  int len = 0;
  while (len < sizeof(buf))
  {
    uint8_t byte;
    if (uart_poll_in(uart_dev, &byte) == 0) {
        buf[len] = byte;
        len=len+1;
    }
    else {
      k_msleep(1);
    }
  }
  
  if (len > 0)
  { 
    // read 4 bytes network id and 2 bytes channel
    NETWORK_ID = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0]; 
    CARRIER = (buf[5] << 8) | buf[4];
    
    printk("configured NETWORK_ID 0x%X CARRIER %d\n", NETWORK_ID, CARRIER);
    
  }
  return;
}

int main(void)
{
  int err = 0;

  k_msleep(100);


  err = nrf_modem_lib_init();
  if (err)
  {
    printk("modem init failed, err %d\n", err);
    return err;
  }
  
  err = nrf_modem_dect_phy_event_handler_set(dect_phy_event_handler);
  if (err)
  {
    printk("nrf_modem_dect_phy_event_handler_set failed, err %d\n", err);
    return err;
  }

  k_sem_take(&operation_sem, K_FOREVER);
  err = nrf_modem_dect_phy_init();
  if (err)
  {
    printk("nrf_modem_dect_phy_init failed, err %d\n", err);
    return err;
  }

  k_sem_take(&operation_sem, K_FOREVER);
  err = nrf_modem_dect_phy_configure(&dect_phy_config_params);
  if (err)
  {
    printk("nrf_modem_dect_phy_configure failed, err %d\n", err);
    return err;
  }

  k_sem_take(&operation_sem, K_FOREVER);
  err = nrf_modem_dect_phy_activate(NRF_MODEM_DECT_PHY_RADIO_MODE_LOW_LATENCY);
  if (err)
  {
    printk("nrf_modem_dect_phy_activate failed, err %d\n", err);
    return err;
  }

  k_work_queue_init(&work_q);
  printk("Waiting configuration from serial: NETWORK_ID CARRIER numbers\n");

  read_serial();

	k_work_queue_start(&work_q, work_queue_stack,K_THREAD_STACK_SIZEOF(work_queue_stack),WORKQ_PRIO, NULL);
  for (int i = 0; i < MAX_WORKER_BUFS; i++) {
    struct worker_buf *buf = &worker_buf_pool[i];
    buf->is_pcc = false;
    buf->flush = false;
    buf->len = 0;
    memset(buf->rx_bytes, 0, sizeof(buf->rx_bytes));
    k_msgq_put(&worker_buf_q, &buf, K_NO_WAIT);
  }
  printk("DECT sniffer listening on channel %d\n", CARRIER);

  while (0 == EXIT)
  {
    // loop RX mode
    //modem_rx(NRF_MODEM_DECT_PHY_RX_MODE_CONTINUOUS, 10);
    modem_rx(NRF_MODEM_DECT_PHY_RX_MODE_SINGLE_SHOT, 10);
  
  }
  // messages may be in logging pipeline, wait a sec
  k_msleep(1000);
  printk("\nEXIT Listening\n");
  return 0;
}
