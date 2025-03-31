/******************************************************************************
Copyright (c) 2023  Nordic Semiconductor ASA
SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************
Simple sniffer, prints out messages seen on the air DECT-2020

MUST CONFIGURE the newtork ID to descramble messages. default is network_id=0x12345678
as used in dect-shell sample form nordic.
Prepends strings with H == PCC header and length byte in HEX
  PCC error is H00
Prepends strings with P == PDC header and 2 length bytes in HEX
  PDC error is P0000
these values are easy to remove from the hex strings in PC side before sending to
wireshark or similar.
****************************************************************************
TODO:
-
****************************************************************************/

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <nrf_modem_dect_phy.h>
#include <modem/nrf_modem_lib.h>

LOG_MODULE_REGISTER(app);

// handle values for API calls, separate tx and rx
int rxHandle = 31400;
int EXIT = 0;
uint8_t pcc_data[21];
uint8_t pdc_data[1200];
uint8_t hdr[10];

// Note that the MCS impacts how much data can be fit into subslots/slots
#define MCS 1
#define CARRIER 1677

// semaphore for API calls, only 1 async operation at time in this sample
K_SEM_DEFINE(operation_sem, 1, 1);

static struct nrf_modem_dect_phy_config_params dect_phy_config_params = {
    .band_group_index = 0,
    .harq_rx_process_count = 4,
    .harq_rx_expiry_time_us = 5000000};

/* Callback after init operation. */
static void on_init(const struct nrf_modem_dect_phy_init_event *evt)
{
  if (evt->err)
  {
    printk("ERROR Init failed, err %d", evt->err);
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
    printk("ERROR Deinit failed, err %d", evt->err);
    return;
  }

  k_sem_give(&operation_sem);
}

static void on_activate(const struct nrf_modem_dect_phy_activate_event *evt)
{
  if (evt->err)
  {
    printk("ERROR Activate failed, err %d", evt->err);
    EXIT = true;
    return;
  }

  k_sem_give(&operation_sem);
}

static void on_deactivate(const struct nrf_modem_dect_phy_deactivate_event *evt)
{

  if (evt->err)
  {
    printk("ERROR Deactivate failed, err %d", evt->err);
    return;
  }

  k_sem_give(&operation_sem);
}

static void on_configure(const struct nrf_modem_dect_phy_configure_event *evt)
{
  if (evt->err)
  {
    printk("ERROR Configure failed callback err %d", evt->err);
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
    printk("ERROR Radio config failed, err %d", evt->err);
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

/* Operation complete notification. */
static void on_op_complete(const struct nrf_modem_dect_phy_op_complete_event *evt)
{
  k_sem_give(&operation_sem);
  return;
}

/* Physical Control Channel reception notification. */
static void on_pcc(const struct nrf_modem_dect_phy_pcc_event *evt)
{
  union nrf_modem_dect_phy_hdr hdr=evt->hdr;
  int i=0;
  int l = 0;
  if (evt->phy_type == 1)
  {
    l = 10;
    for (i = 0; i < l; i++)
    {
      sprintf(&pcc_data[i * 2], "%02X", hdr.type_2[i]);
    }
  }
  else
  {
    l = 5;
    for (i = 0; i < l; i++)
    {
      sprintf(&pcc_data[i * 2], "%02X", hdr.type_1[i]);
    }
  }
  printk("H%02X%s\n", l, pcc_data);
  return;
}

/* Physical Control Channel CRC error notification. */
static void on_pcc_crc_err(const struct nrf_modem_dect_phy_pcc_crc_failure_event *evt)
{
  printk("H%02X\n", 0);
}

/* Physical Data Channel reception notification. */
static void on_pdc(const struct nrf_modem_dect_phy_pdc_event *evt)
{
  int i;
  for (i = 0; i < evt->len; i++)
  {
    sprintf(&pdc_data[i * 2], "%02X", ((uint8_t *)evt->data)[i]);
  }
  printk("P%s\n", pdc_data);
  return;
}

/* Physical Data Channel CRC error notification. */
static void on_pdc_crc_err(const struct nrf_modem_dect_phy_pdc_crc_failure_event *evt)
{
  printk("P%04X%s\n", 0);
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
  rxOpsParams.network_id = 0x12345678;
  rxOpsParams.mode = rxMode;
  rxOpsParams.rssi_interval = NRF_MODEM_DECT_PHY_RSSI_INTERVAL_OFF;
  rxOpsParams.link_id = NRF_MODEM_DECT_PHY_LINK_UNSPECIFIED;
  rxOpsParams.rssi_level = 0;
  rxOpsParams.carrier = CARRIER;
  // modem clock ticks NRF_MODEM_DECT_MODEM_TIME_TICK_RATE_KHZ --> 69120*1000* TIME_S
  rxOpsParams.duration = time_s * 69120 * 1000;
  // filter on the short network id, last 8 bits of the network identifier in dect nr
  rxOpsParams.filter.short_network_id = (uint8_t)(0xaa);
  rxOpsParams.filter.is_short_network_id_used = 0;
  // listen for everything (broadcast mode usedd)
  rxOpsParams.filter.receiver_identity = 0;
  k_sem_take(&operation_sem, K_FOREVER);
  int err = nrf_modem_dect_phy_rx(&rxOpsParams);
  if (err != 0)
    printk("RX FAIL %d", err);
  if (rxHandle == 65000)
    rxHandle = 31400;
  else
    rxHandle++;
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

  printk("DECT sniffer listening on channel %d\n", CARRIER);

  while (0 == EXIT)
  {
    // loop RX mode
    modem_rx(NRF_MODEM_DECT_PHY_RX_MODE_CONTINUOUS, 10);
  }
  // messages may be in logging pipeline, wait a sec
  k_msleep(1000);
  printk("\nEXIT Listening\n");
  return 0;
}
