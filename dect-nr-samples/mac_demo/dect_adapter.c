/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include "dect_adapter.h"

#include <errno.h>
#include <modem/nrf_modem_lib.h>
#include <nrf_modem_dect.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(dect_adapter, CONFIG_LOG_DEFAULT_LEVEL);

/* ============================================================================
 * INTERNAL STATE
 * ========================================================================== */

static struct dect_adapter_op_callbacks app_op_cbs;
static struct dect_adapter_ntf_callbacks app_ntf_cbs;
static uint32_t beacon_period_ms;  /* Last received beacon period in milliseconds */

/* ============================================================================
 * INTERNAL UTILITY FUNCTIONS (not exported)
 * ========================================================================== */

static enum nrf_modem_dect_mac_band_group_index band_group_from_carrier(uint16_t carrier)
{
	return (carrier >= 525U && carrier <= 551U) ?
		NRF_MODEM_DECT_MAC_PHY_BAND_GROUP_IDX1 : NRF_MODEM_DECT_MAC_PHY_BAND_GROUP_IDX0;
}

static enum nrf_modem_dect_mac_band band_from_carrier(uint16_t carrier)
{
	return (carrier >= 525U && carrier <= 551U) ?
		NRF_MODEM_DECT_MAC_PHY_BAND4 : NRF_MODEM_DECT_MAC_PHY_BAND1;
}

static enum nrf_modem_dect_mac_nw_beacon_period nw_beacon_period_from_ms(uint32_t ms)
{
	switch (ms) {
	case 50:   return NRF_MODEM_DECT_MAC_NW_BEACON_PERIOD_50_MS;
	case 100:  return NRF_MODEM_DECT_MAC_NW_BEACON_PERIOD_100_MS;
	case 500:  return NRF_MODEM_DECT_MAC_NW_BEACON_PERIOD_500_MS;
	case 1000: return NRF_MODEM_DECT_MAC_NW_BEACON_PERIOD_1000_MS;
	case 1500: return NRF_MODEM_DECT_MAC_NW_BEACON_PERIOD_1500_MS;
	case 2000: return NRF_MODEM_DECT_MAC_NW_BEACON_PERIOD_2000_MS;
	case 4000: return NRF_MODEM_DECT_MAC_NW_BEACON_PERIOD_4000_MS;
	default:   return NRF_MODEM_DECT_MAC_NW_BEACON_PERIOD_1000_MS;
	}
}

static enum nrf_modem_dect_mac_cluster_beacon_period cluster_beacon_period_from_ms(uint32_t ms)
{
	switch (ms) {
	case 10:    return NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_10_MS;
	case 50:    return NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_50_MS;
	case 100:   return NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_100_MS;
	case 500:   return NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_500_MS;
	case 1000:  return NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_1000_MS;
	case 1500:  return NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_1500_MS;
	case 2000:  return NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_2000_MS;
	case 4000:  return NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_4000_MS;
	case 8000:  return NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_8000_MS;
	case 16000: return NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_16000_MS;
	case 32000: return NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_32000_MS;
	default:    return NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_1000_MS;
	}
}

static uint32_t cluster_beacon_period_to_ms(enum nrf_modem_dect_mac_cluster_beacon_period period)
{
	switch (period) {
	case NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_10_MS:    return 10;
	case NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_50_MS:    return 50;
	case NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_100_MS:   return 100;
	case NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_500_MS:   return 500;
	case NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_1000_MS:  return 1000;
	case NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_1500_MS:  return 1500;
	case NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_2000_MS:  return 2000;
	case NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_4000_MS:  return 4000;
	case NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_8000_MS:  return 8000;
	case NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_16000_MS: return 16000;
	case NRF_MODEM_DECT_MAC_CLUSTER_BEACON_PERIOD_32000_MS: return 32000;
	default: return 1000;
	}
}

/* ============================================================================
 * INTERNAL nrf_modem CALLBACKS — translate to app callbacks
 * ========================================================================== */

static void internal_op_functional_mode_cb(
	struct nrf_modem_dect_mac_control_functional_mode_cb_params *params)
{
	LOG_DBG("op functional_mode callback: status=%d", params->status);
	if (app_op_cbs.functional_mode) {
		app_op_cbs.functional_mode(params->status);
	}
}

static void internal_op_configure_cb(
	struct nrf_modem_dect_mac_control_configure_cb_params *params)
{
	LOG_DBG("op configure callback: status=%d", params->status);
	if (app_op_cbs.configure) {
		app_op_cbs.configure(params->status);
	}
}

static void internal_op_systemmode_cb(
	struct nrf_modem_dect_mac_control_systemmode_cb_params *params)
{
	LOG_DBG("op systemmode callback: status=%d", params->status);
	if (app_op_cbs.systemmode) {
		app_op_cbs.systemmode(params->status);
	}
}

static void internal_op_cluster_configure_cb(
	struct nrf_modem_dect_mac_cluster_configure_cb_params *params)
{
	LOG_INF("cluster_configure callback status=%d", params->status);
	if (app_op_cbs.cluster_configure) {
		app_op_cbs.cluster_configure(params->status);
	}
}

static void internal_op_cluster_beacon_receive_cb(
	struct nrf_modem_dect_mac_cluster_beacon_receive_cb_params *params)
{
	int status = (params->num_clusters > 0) ?
		params->cluster_status[0] : NRF_MODEM_DECT_MAC_STATUS_FAIL;

	LOG_DBG("cluster_beacon_receive callback status=%d clusters=%u", status, params->num_clusters);
	if (app_op_cbs.cluster_beacon_receive) {
		app_op_cbs.cluster_beacon_receive(status);
	}
}

static void internal_op_cluster_beacon_receive_stop_cb(
	struct nrf_modem_dect_mac_cluster_beacon_receive_stop_cb_params *params)
{
	LOG_DBG("op cluster_beacon_receive_stop callback: status=%d", params->status);
	if (app_op_cbs.cluster_beacon_receive_stop) {
		app_op_cbs.cluster_beacon_receive_stop(params->status);
	}
}

static void internal_op_network_beacon_configure_cb(
	struct nrf_modem_dect_mac_network_beacon_configure_cb_params *params)
{
	LOG_DBG("network_beacon_configure callback status=%d", params->status);
	if (app_op_cbs.network_beacon_configure) {
		app_op_cbs.network_beacon_configure(params->status);
	}
}

static void internal_op_network_scan_cb(
	struct nrf_modem_dect_mac_network_scan_cb_params *params)
{
	LOG_INF("network_scan callback status=%d scanned_channels=%u", params->status, params->num_scanned_channels);
	if (app_op_cbs.network_scan) {
		app_op_cbs.network_scan(params->status);
	}
}

static void internal_op_network_scan_stop_cb(
	struct nrf_modem_dect_mac_network_scan_stop_cb_params *params)
{
	LOG_DBG("op network_scan_stop callback: status=%d", params->status);
	if (app_op_cbs.network_scan_stop) {
		app_op_cbs.network_scan_stop(params->status);
	}
}

static void internal_op_rssi_scan_cb(
	struct nrf_modem_dect_mac_rssi_scan_cb_params *params)
{
	LOG_DBG("op rssi_scan callback: status=%d", params->status);
	if (app_op_cbs.rssi_scan) {
		app_op_cbs.rssi_scan(params->status);
	}
}

static void internal_op_rssi_scan_stop_cb(
	struct nrf_modem_dect_mac_rssi_scan_stop_cb_params *params)
{
	LOG_DBG("op rssi_scan_stop callback: status=%d", params->status);
	if (app_op_cbs.rssi_scan_stop) {
		app_op_cbs.rssi_scan_stop(params->status);
	}
}

static void internal_op_dlc_data_tx_cb(
	struct nrf_modem_dect_dlc_data_tx_cb_params *params)
{
	LOG_DBG("op dlc_data_tx callback: status=%d txn=%u flow=%u rd=%u",
		params->status, params->transaction_id, params->flow_id, params->long_rd_id);
	if (app_op_cbs.dlc_data_tx) {
		app_op_cbs.dlc_data_tx(params->status, params->transaction_id);
	}
}

static void internal_op_dlc_data_discard_cb(
	struct nrf_modem_dect_dlc_data_discard_cb_params *params)
{
	LOG_DBG("op dlc_data_discard callback: status=%d txn=%u flow=%u rd=%u",
		params->status, params->transaction_id, params->flow_id, params->long_rd_id);
}

static void internal_op_association_release_cb(
	struct nrf_modem_dect_mac_association_release_cb_params *params)
{
	LOG_DBG("op association_release callback: rd=%u", params->long_rd_id);
}

static void internal_op_cluster_info_cb(
	struct nrf_modem_dect_mac_cluster_info_cb_params *params)
{
	LOG_DBG("op cluster_info callback: status=%d", params->status);
}

static void internal_op_neighbor_info_cb(
	struct nrf_modem_dect_mac_neighbor_info_cb_params *params)
{
	LOG_DBG("op neighbor_info callback: status=%d rd=%u", params->status, params->long_rd_id);
}

static void internal_op_neighbor_list_cb(
	struct nrf_modem_dect_mac_neighbor_list_cb_params *params)
{
	LOG_DBG("op neighbor_list callback: status=%d neighbors=%u", params->status, params->num_neighbors);
}

/* Operation callback: PT receives association response */
static void internal_op_association_cb(
	struct nrf_modem_dect_mac_association_cb_params *params)
{
	LOG_DBG("op association callback: status=%d rd=%u", params->status, params->long_rd_id);
	if (app_ntf_cbs.association_ntf) {
		app_ntf_cbs.association_ntf(params->status, params->long_rd_id);
	}
}

/* Notification callbacks */
static void internal_ntf_association_release_cb(
	struct nrf_modem_dect_mac_association_release_ntf_cb_params *params)
{
	LOG_DBG("ntf association_release callback: rd=%u cause=%d", params->long_rd_id, params->release_cause);
	if (app_ntf_cbs.association_release_ntf) {
		app_ntf_cbs.association_release_ntf(params->long_rd_id);
	}
}

static void internal_ntf_association_ind_cb(
	struct nrf_modem_dect_mac_association_ntf_cb_params *params)
{
	LOG_INF("FT association indication: status=%d rd=%u short_rd=%u ies=%u tx_method=%u",
		params->status, params->long_rd_id, params->short_rd_id,
		params->number_of_ies, params->tx_method);

	/* FT side: a PT has associated */
	if (app_ntf_cbs.association_ind_ntf) {
		app_ntf_cbs.association_ind_ntf(params->status, params->long_rd_id);
	}
}

static size_t count_bits(const uint8_t *arr, size_t byte_len)
{
	size_t count = 0;

	for (size_t i = 0; i < byte_len; i++) {
		count += __builtin_popcount(arr[i]);
	}
	return count;
}

static void internal_ntf_rssi_scan_cb(
	struct nrf_modem_dect_mac_rssi_scan_ntf_cb_params *params)
{
	LOG_DBG("ntf rssi_scan callback: ch=%u busy=%u%%", params->channel, params->busy_percentage);
	if (app_ntf_cbs.rssi_scan_ntf) {
		size_t total_slots    = params->rssi_meas_array_size * 8U;
		size_t free_slots     = params->free     ? count_bits(params->free,     params->rssi_meas_array_size) : 0;
		size_t possible_slots = params->possible ? count_bits(params->possible, params->rssi_meas_array_size) : 0;

		app_ntf_cbs.rssi_scan_ntf(params->channel, params->busy_percentage,
					   free_slots, possible_slots, total_slots);
	}
}

static void internal_ntf_cluster_beacon_cb(
	struct nrf_modem_dect_mac_cluster_beacon_ntf_cb_params *params)
{
	uint32_t period_ms = cluster_beacon_period_to_ms(params->beacon.cluster_beacon_period);

	beacon_period_ms = period_ms;

	LOG_DBG("cluster beacon ntf callback: ch=%u nw=%u rd=%u period=%u ms",
		params->channel, params->network_id, params->transmitter_long_rd_id, period_ms);
	if (app_ntf_cbs.cluster_beacon_ntf) {
		app_ntf_cbs.cluster_beacon_ntf(
			params->channel, params->network_id, params->transmitter_long_rd_id,
			period_ms, params->rx_signal_info.rssi_2);
	}
}

static void internal_ntf_cluster_beacon_rx_failure_cb(
	struct nrf_modem_dect_mac_cluster_beacon_rx_failure_ntf_cb_params *params)
{
	LOG_DBG("ntf cluster_beacon_rx_failure callback: rd=%u", params->long_rd_id);
	if (app_ntf_cbs.cluster_beacon_rx_failure_ntf) {
		app_ntf_cbs.cluster_beacon_rx_failure_ntf(params->long_rd_id);
	}
}

static void internal_ntf_network_beacon_cb(
	struct nrf_modem_dect_mac_network_beacon_ntf_cb_params *params)
{
	uint32_t period_ms = cluster_beacon_period_to_ms(params->beacon.cluster_beacon_period);
	beacon_period_ms = period_ms;

	LOG_DBG("network beacon ntf callback: ch=%u nw=%u rd=%u cluster_period=%u ms",
		params->channel, params->network_id, params->transmitter_long_rd_id, period_ms);
	if (app_ntf_cbs.network_beacon_ntf) {
		app_ntf_cbs.network_beacon_ntf(
			params->channel, params->network_id, params->transmitter_long_rd_id,
			period_ms, params->rx_signal_info.rssi_2);
	}
}

static void internal_ntf_dlc_data_rx_cb(
	struct nrf_modem_dect_dlc_data_rx_ntf_cb_params *params)
{
	LOG_INF("ntf dlc_data_rx callback: rd=%u flow=%u len=%zu",
		params->long_rd_id, params->flow_id, params->data_len);
	if (app_ntf_cbs.dlc_data_rx_ntf) {
		app_ntf_cbs.dlc_data_rx_ntf(params->long_rd_id, params->data, params->data_len);
	}
}

static void internal_ntf_cluster_ch_load_change_cb(
	struct nrf_modem_dect_mac_cluster_ch_load_change_ntf_cb_params *params)
{
	LOG_DBG("ntf cluster_ch_load_change callback: ch=%u busy=%u%%",
		params->rssi_result.channel, params->rssi_result.busy_percentage);
}

static void internal_ntf_neighbor_inactivity_cb(
	struct nrf_modem_dect_mac_neighbor_inactivity_ntf_cb_params *params)
{
	LOG_DBG("ntf neighbor_inactivity callback: rd=%u", params->long_rd_id);
}

static void internal_ntf_neighbor_paging_failure_cb(
	struct nrf_modem_dect_mac_neighbor_paging_failure_ntf_cb_params *params)
{
	LOG_DBG("ntf neighbor_paging_failure callback: rd=%u", params->long_rd_id);
}

static void internal_ntf_ipv6_config_update_cb(
	struct nrf_modem_dect_mac_ipv6_config_update_ntf_cb_params *params)
{
	ARG_UNUSED(params);
	LOG_DBG("ntf ipv6_config_update callback");
}

static void internal_ntf_capability_cb(
	struct nrf_modem_dect_mac_capability_ntf_cb_params *params)
{
	LOG_DBG("capability callback: max_mcs=%u, bands=%u", params->max_mcs, params->num_band_info_elems);
	for (uint8_t i = 0; i < params->num_band_info_elems; i++) {
		LOG_INF("capability callback band[%u]: band=%u group=%u min=%u max=%u", i,
			params->band_info_elems[i].band,
			params->band_info_elems[i].band_group_index,
			params->band_info_elems[i].min_carrier,
			params->band_info_elems[i].max_carrier);
	}
}

static void internal_ntf_dlc_flow_control_cb(
	struct nrf_modem_dect_dlc_flow_control_ntf_cb_params *params)
{
	LOG_DBG("ntf dlc_flow_control callback: status=%d", params->status);
}

static const struct nrf_modem_dect_mac_op_callbacks internal_op_callbacks = {
	.control_functional_mode  = internal_op_functional_mode_cb,
	.control_configure        = internal_op_configure_cb,
	.control_systemmode       = internal_op_systemmode_cb,
	.association              = internal_op_association_cb,
	.association_release      = internal_op_association_release_cb,
	.cluster_beacon_receive   = internal_op_cluster_beacon_receive_cb,
	.cluster_beacon_receive_stop = internal_op_cluster_beacon_receive_stop_cb,
	.cluster_configure        = internal_op_cluster_configure_cb,
	.cluster_info             = internal_op_cluster_info_cb,
	.neighbor_info            = internal_op_neighbor_info_cb,
	.neighbor_list            = internal_op_neighbor_list_cb,
	.dlc_data_tx              = internal_op_dlc_data_tx_cb,
	.dlc_data_discard         = internal_op_dlc_data_discard_cb,
	.network_beacon_configure = internal_op_network_beacon_configure_cb,
	.network_scan             = internal_op_network_scan_cb,
	.network_scan_stop        = internal_op_network_scan_stop_cb,
	.rssi_scan                = internal_op_rssi_scan_cb,
	.rssi_scan_stop           = internal_op_rssi_scan_stop_cb,
};

static const struct nrf_modem_dect_mac_ntf_callbacks internal_ntf_callbacks = {
	.association_ntf              = internal_ntf_association_ind_cb,
	.association_release_ntf      = internal_ntf_association_release_cb,
	.cluster_ch_load_change_ntf   = internal_ntf_cluster_ch_load_change_cb,
	.neighbor_inactivity_ntf      = internal_ntf_neighbor_inactivity_cb,
	.neighbor_paging_failure_ntf  = internal_ntf_neighbor_paging_failure_cb,
	.rssi_scan_ntf                = internal_ntf_rssi_scan_cb,
	.cluster_beacon_ntf           = internal_ntf_cluster_beacon_cb,
	.cluster_beacon_rx_failure_ntf = internal_ntf_cluster_beacon_rx_failure_cb,
	.ipv6_config_update_ntf       = internal_ntf_ipv6_config_update_cb,
	.network_beacon_ntf           = internal_ntf_network_beacon_cb,
	.dlc_data_rx_ntf              = internal_ntf_dlc_data_rx_cb,
	.capability_ntf               = internal_ntf_capability_cb,
	.dlc_flow_control_ntf         = internal_ntf_dlc_flow_control_cb,
};

/* ============================================================================
 * PUBLIC API
 * ========================================================================== */

int dect_adapter_init(void)
{
	int err;

	err = nrf_modem_lib_init();
	if (err != 0) {
		LOG_ERR("nrf_modem_lib_init failed: %d", err);
	}
	return err;
}

int dect_adapter_callbacks_set(
	const struct dect_adapter_op_callbacks *op_cbs,
	const struct dect_adapter_ntf_callbacks *ntf_cbs)
{
	int err;

	if (!op_cbs || !ntf_cbs) {
		return -EINVAL;
	}

	app_op_cbs = *op_cbs;
	app_ntf_cbs = *ntf_cbs;

	err = nrf_modem_dect_mac_callback_set(&internal_op_callbacks, &internal_ntf_callbacks);
	if (err != 0) {
		LOG_ERR("nrf_modem_dect_mac_callback_set failed: %d", err);
	}
	return err;
}

int dect_adapter_system_mode_set_mac(void)
{
	int err;

	err = nrf_modem_dect_control_systemmode_set(NRF_MODEM_DECT_MODE_MAC);
	if (err != 0) {
		LOG_ERR("systemmode_set failed: %d", err);
	}
	return err;
}

int dect_adapter_control_configure(
	int max_tx_power_dbm,
	int max_mcs,
	int rx_expected_rssi,
	uint32_t long_rd_id,
	uint16_t carrier,
	bool powersave)
{
	int err;
	struct nrf_modem_dect_control_configure_params params = {0};
	
	params.max_tx_power = 14;
	params.max_mcs = max_mcs;
	params.expected_mcs1_rx_rssi_level = rx_expected_rssi;
	params.long_rd_id = long_rd_id;
	params.phy_band_group_index = band_group_from_carrier(carrier);
	params.power_save = powersave;
	params.security.mode = NRF_MODEM_DECT_MAC_SECURITY_MODE_NONE;
	/* Security mode 1 hardcoded keys
	params.security.mode = NRF_MODEM_DECT_MAC_SECURITY_MODE_1;
	static const uint8_t integrity_key[16] = {
		0x4a, 0x75, 0x73, 0x74, 0x41, 0x64, 0x65, 0x66,
		0x61, 0x75, 0x6c, 0x74, 0x21, 0x21, 0x21, 0x21};
	static const uint8_t cipher_key[16] = {
		0x4a, 0x75, 0x73, 0x74, 0x41, 0x64, 0x65, 0x66,
		0x61, 0x75, 0x6c, 0x74, 0x21, 0x21, 0x21, 0x21};
	memcpy(params.security.integrity_key, integrity_key, sizeof(integrity_key));
	memcpy(params.security.cipher_key, cipher_key, sizeof(cipher_key));
	*/
	params.stats_averaging_length = 2;

	printk("Device control_configure: tx=%d dBm mcs=%d rd=%u carrier=%u pwrsave=%u \n",
		max_tx_power_dbm, max_mcs, long_rd_id, carrier, powersave);
	err = nrf_modem_dect_control_configure(&params);
	if (err != 0) {
		LOG_ERR("control_configure failed: %d", err);
	}
	return err;
}

int dect_adapter_functional_mode_set(bool activate)
{
	int err;

	err = nrf_modem_dect_control_functional_mode_set(
		activate ? NRF_MODEM_DECT_CONTROL_FUNCTIONAL_MODE_ACTIVATE :
			   NRF_MODEM_DECT_CONTROL_FUNCTIONAL_MODE_DEACTIVATE);
	if (err != 0) {
		LOG_ERR("functional_mode_set(%d) failed: %d", activate, err);
	}
	return err;
}

int dect_adapter_rssi_scan_start(
	uint16_t carrier,
	int threshold_low,
	int threshold_high)
{
	int err;
	struct nrf_modem_dect_mac_rssi_scan_params params = {0};

	params.channel_scan_length = 5;
	params.threshold_min = threshold_low;
	params.threshold_max = threshold_high;
	params.num_channels = 0; /* 0 = scan all channels in band */
	params.band = band_from_carrier(carrier);

	LOG_INF("FT rssi_scan: band=%u thresholds=%d..%d dBm", params.band, threshold_low, threshold_high);
	err = nrf_modem_dect_mac_rssi_scan(&params);
	if (err != 0) {
		LOG_ERR("rssi_scan failed: %d", err);
	}
	return err;
}

int dect_adapter_rssi_scan_stop(void)
{
	int err;

	err = nrf_modem_dect_mac_rssi_scan_stop();
	if (err != 0) {
		LOG_ERR("rssi_scan_stop failed: %d", err);
	}
	return err;
}

int dect_adapter_cluster_configure_ft(
	uint16_t channel,
	uint32_t cluster_beacon_period,
	uint32_t network_id,
	int tx_power_dbm,
	uint8_t rach_fill_percentage)
{
	int err;
	struct nrf_modem_dect_mac_association_config association_config = {0};
	struct nrf_modem_dect_mac_cluster_config cluster_config = {0};
	struct nrf_modem_dect_mac_cluster_configure_params params = {0};

	association_config.max_num_neighbours = 4;
	association_config.max_num_ft_neighbours = 1;
	association_config.default_tx_flow_config[0].dlc_service_type =
		NRF_MODEM_DECT_DLC_SERVICE_TYPE_3;
	association_config.default_tx_flow_config[0].dlc_sdu_lifetime =
		NRF_MODEM_DECT_DLC_SDU_LIFETIME_60_S;
	association_config.default_tx_flow_config[1].dlc_service_type =
		NRF_MODEM_DECT_DLC_SERVICE_TYPE_3;
	association_config.default_tx_flow_config[1].dlc_sdu_lifetime =
		NRF_MODEM_DECT_DLC_SDU_LIFETIME_60_S;
	for (size_t i = 2; i < ARRAY_SIZE(association_config.default_tx_flow_config); i++) {
		association_config.default_tx_flow_config[i].priority = i + 1U;
		association_config.default_tx_flow_config[i].dlc_service_type =
			NRF_MODEM_DECT_DLC_SERVICE_TYPE_3;
		association_config.default_tx_flow_config[i].dlc_sdu_lifetime =
			NRF_MODEM_DECT_DLC_SDU_LIFETIME_60_S;
	}

	cluster_config.flags.has_max_tx_power = 1;
	cluster_config.flags.has_rach_config = 1;
	cluster_config.count_to_trigger = NRF_MODEM_DECT_MAC_COUNT_TO_TRIGGER_2;
	cluster_config.relative_quality = NRF_MODEM_DECT_MAC_QUALITY_THRESHOLD_0;
	cluster_config.min_quality = NRF_MODEM_DECT_MAC_QUALITY_THRESHOLD_0;
	cluster_config.beacon_tx_power = 14;
	cluster_config.cluster_max_tx_power = 14;
	cluster_config.cluster_beacon_period = cluster_beacon_period_from_ms(cluster_beacon_period);
	cluster_config.cluster_channel = channel;
	cluster_config.network_id = network_id;
	cluster_config.rach_configuration.policy = NRF_MODEM_DECT_MAC_RACH_CONFIG_POLICY_FILL;
	cluster_config.rach_configuration.common.response_window_length = 8;
	cluster_config.rach_configuration.common.max_transmission_length = 8;
	cluster_config.rach_configuration.common.cw_min_sig = 1;
	cluster_config.rach_configuration.common.cw_max_sig = 5;
	cluster_config.rach_configuration.config.fill.percentage = rach_fill_percentage;
	cluster_config.triggers.busy_threshold = 70;
	cluster_config.ipv6_config.type = NRF_MODEM_DECT_MAC_IPV6_ADDRESS_TYPE_NONE;
	
	params.cluster_period_start_offset = 0;
	params.association_config = &association_config;
	params.cluster_config = &cluster_config;

	LOG_INF("cluster_configure_ft: ch=%u period=%u ms nw=%u tx=%d dBm",
		channel, cluster_beacon_period, network_id, tx_power_dbm);
	err = nrf_modem_dect_mac_cluster_configure(&params);
	if (err != 0) {
		LOG_ERR("cluster_configure failed: %d", err);
	} else {
		LOG_INF("FT BEACONING - Cluster configured: ch=%u period=%u ms nw=%u tx=%d dBm",
			channel, cluster_beacon_period, network_id, tx_power_dbm);
	}
	return err;
}

int dect_adapter_network_beacon_configure_ft(
	uint16_t channel,
	uint32_t nw_beacon_period)
{
	int err;
	struct nrf_modem_dect_mac_network_beacon_configure_params params = {0};

	params.channel = channel;
	params.nw_beacon_period = nw_beacon_period_from_ms(nw_beacon_period);
	params.num_additional_channels = 0;
	params.additional_channels = NULL;

	LOG_DBG("network_beacon_configure_ft: ch=%u period=%u ms", channel, nw_beacon_period);
	err = nrf_modem_dect_mac_network_beacon_configure(&params);
	if (err != 0) {
		LOG_ERR("network_beacon_configure failed: %d", err);
	} else {
		LOG_INF("FT BEACONING - Network beacon configured: ch=%u period=%u ms",
			channel, nw_beacon_period);
	}
	return err;
}

int dect_adapter_nw_period_from_cluster_period(
	uint32_t cluster_period_ms,
	uint32_t *network_period_ms)
{
	if (cluster_period_ms < 50) {
		*network_period_ms = 50;
		return 0;
	}
	if (cluster_period_ms < 100) {
		*network_period_ms = 100;
		return 0;
	}
	if (cluster_period_ms < 500) {
		*network_period_ms = 500;
		return 0;
	}
	if (cluster_period_ms < 1000) {
		*network_period_ms = 1000;
		return 0;
	}
	if (cluster_period_ms < 1500) {
		*network_period_ms = 1500;
		return 0;
	}
	if (cluster_period_ms < 2000) {
		*network_period_ms = 2000;
		return 0;
	}
	if (cluster_period_ms < 4000) {
		*network_period_ms = 4000;
		return 0;
	}
	return -EINVAL;
}

int dect_adapter_network_scan_start(
	uint16_t channel,
	uint32_t scan_time_ms,
	uint32_t network_id_filter)
{
	int err;
	struct nrf_modem_dect_mac_network_scan_params params = {0};

	params.network_id_filter_mode = (network_id_filter == 0) ?
		NRF_MODEM_DECT_MAC_NW_ID_FILTER_MODE_NONE :
		NRF_MODEM_DECT_MAC_NW_ID_FILTER_MODE_32BIT;
	params.network_id_filter = network_id_filter;
	params.scan_time = scan_time_ms;
	params.band = band_from_carrier(channel);
	if (channel != 0U) {
		params.num_channels = 1;
		params.channel_list[0] = channel;
	} else {
		params.num_channels = 0; /* 0 = scan all channels in band */
	}

	LOG_INF("PT network_scan: band=%u channel=%u num_channels=%u dwell=%u ms",
		params.band, channel, params.num_channels, scan_time_ms);
	err = nrf_modem_dect_mac_network_scan(&params);
	if (err != 0) {
		LOG_ERR("network_scan failed: %d", err);
	}
	return err;
}

int dect_adapter_network_scan_stop(void)
{
	int err;

	err = nrf_modem_dect_mac_network_scan_stop();
	if (err != 0) {
		LOG_ERR("network_scan_stop failed: %d", err);
	}
	return err;
}

int dect_adapter_cluster_beacon_receive_start(
	uint16_t channel,
	uint32_t cluster_beacon_period,
	uint32_t parent_long_rd_id,
	uint32_t network_id)
{
	int err;
	struct nrf_modem_dect_mac_cluster_beacon_config config = {0};
	struct nrf_modem_dect_mac_cluster_beacon_receive_params params = {0};

	config.cluster_channel = channel;
	config.cluster_beacon_period = cluster_beacon_period_from_ms(cluster_beacon_period);
	config.long_rd_id = parent_long_rd_id;
	config.network_id = network_id;

	params.num_configs = 1;
	params.configs = &config;

	LOG_DBG("cluster_beacon_receive: ch=%u period=%u ms nw=%u rd=%u",
		channel, cluster_beacon_period, network_id, parent_long_rd_id);
	err = nrf_modem_dect_mac_cluster_beacon_receive(&params);
	if (err != 0) {
		LOG_ERR("cluster_beacon_receive failed: %d", err);
	}
	return err;
}

int dect_adapter_cluster_beacon_receive_stop(void)
{
	int err;

	err = nrf_modem_dect_mac_cluster_beacon_receive_stop();
	if (err != 0) {
		LOG_ERR("cluster_beacon_receive_stop failed: %d", err);
	}
	return err;
}

int dect_adapter_association_request(
	uint32_t peer_long_rd_id,
	uint32_t network_id)
{
	int err;
	struct nrf_modem_dect_mac_tx_flow_config flow_configs[3] = {
		/* flow_id 1 and 2 are higher-layer signalling flows with fixed priority */
		{ .flow_id = 1, .dlc_service_type = NRF_MODEM_DECT_DLC_SERVICE_TYPE_3,
		  .dlc_sdu_lifetime = NRF_MODEM_DECT_DLC_SDU_LIFETIME_60_S },
		{ .flow_id = 2, .dlc_service_type = NRF_MODEM_DECT_DLC_SERVICE_TYPE_3,
		  .dlc_sdu_lifetime = NRF_MODEM_DECT_DLC_SDU_LIFETIME_60_S },
		/* flow_id 3+ are user plane flows; priority must be in range [3, 6] */
		{ .flow_id = 3, .priority = 3, .dlc_service_type = NRF_MODEM_DECT_DLC_SERVICE_TYPE_3,
		  .dlc_sdu_lifetime = NRF_MODEM_DECT_DLC_SDU_LIFETIME_60_S },
	};
	struct nrf_modem_dect_mac_association_params params = {
		.long_rd_id = peer_long_rd_id,
		.network_id = network_id,
		.info_triggers = {
			.num_beacon_rx_failures = 3,
		},
		.num_flows = 3,
		.tx_flow_configs = flow_configs,
	};

	LOG_INF("association_request: rd=%u nw=%u flows=3", peer_long_rd_id, network_id);
	err = nrf_modem_dect_mac_association(&params);
	if (err != 0) {
		LOG_ERR("association_request failed: %d", err);
	}
	return err;
}

int dect_adapter_association_release(uint32_t peer_long_rd_id)
{
	int err;
	struct nrf_modem_dect_mac_association_release_params params = {
		.release_cause = NRF_MODEM_DECT_MAC_RELEASE_CAUSE_CONNECTION_TERMINATION,
		.long_rd_id    = peer_long_rd_id,
	};

	LOG_INF("association_release: rd=%u", peer_long_rd_id);
	err = nrf_modem_dect_mac_association_release(&params);
	if (err != 0) {
		LOG_ERR("association_release failed: %d", err);
	}
	return err;
}

int dect_adapter_dlc_data_send(
	uint32_t transaction_id,
	uint8_t flow_id,
	uint32_t peer_long_rd_id,
	const void *data,
	size_t data_len)
{
	int err;
	struct nrf_modem_dect_dlc_data_tx_params params = {0};

	if (!data || data_len == 0) {
		return -EINVAL;
	}

	params.transaction_id = transaction_id;
	params.flow_id = flow_id;
	params.long_rd_id = peer_long_rd_id;
	params.data = data;
	params.data_len = data_len;

	err = nrf_modem_dect_dlc_data_tx(&params);
	if (err != 0) {
		LOG_ERR("dlc_data_tx failed: %d", err);
	}
	return err;
}
