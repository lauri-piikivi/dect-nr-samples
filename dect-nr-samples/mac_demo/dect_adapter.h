/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef DECT_ADAPTER_H__
#define DECT_ADAPTER_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file dect_adapter.h
 * @brief DECT MAC API adapter for nRF9151 DECT NR+ communication.
 *
 * This adapter encapsulates all nrf_modem_dect_* and nrf_modem_lib API calls.
 * main.c has no direct dependency on nrf_modem_dect.h or nrf_modem.h.
 */

/* ============================================================================
 * CALLBACK STRUCTS (primitive types only — no nrf_modem types)
 * ========================================================================== */

/** Operation completion callbacks (one per async operation). */
struct dect_adapter_op_callbacks {
	void (*functional_mode)(int status);
	void (*configure)(int status);
	void (*systemmode)(int status);
	void (*cluster_configure)(int status);
	void (*cluster_beacon_receive)(int status);
	void (*cluster_beacon_receive_stop)(int status);
	void (*network_beacon_configure)(int status);
	void (*network_scan)(int status);
	void (*network_scan_stop)(int status);
	void (*rssi_scan)(int status);
	void (*rssi_scan_stop)(int status);
	void (*dlc_data_tx)(int status, uint32_t transaction_id);
};

/** Asynchronous notification callbacks. */
struct dect_adapter_ntf_callbacks {
	/** Association accepted/rejected by FT (PT side). */
	void (*association_ntf)(int status, uint32_t long_rd_id);
	/** Association released by peer. */
	void (*association_release_ntf)(uint32_t long_rd_id);
	/** PT successfully associated with FT (FT side notification). */
	void (*association_ind_ntf)(int status, uint32_t long_rd_id);
	/** RSSI measurement result for one channel. */
	void (*rssi_scan_ntf)(uint16_t channel, uint8_t busy_percentage,
			      size_t free_slots, size_t possible_slots, size_t total_slots);
	/** Cluster beacon received from FT. cluster_beacon_period_ms is the FT's beacon period. */
	void (*cluster_beacon_ntf)(uint16_t channel, uint32_t network_id, uint32_t long_rd_id,
				   uint32_t cluster_beacon_period_ms, int16_t rssi_dbm);
	/** Network beacon received from FT. cluster_beacon_period_ms is the FT's beacon period. */
	void (*network_beacon_ntf)(uint16_t channel, uint32_t network_id, uint32_t long_rd_id,
				   uint32_t cluster_beacon_period_ms, int16_t rssi_dbm);
	/** DLC data received from peer. */
	void (*dlc_data_rx_ntf)(uint32_t long_rd_id, const void *data, size_t data_len);
	/** Cluster beacon RX failure (PT side): FT beacon no longer received. */
	void (*cluster_beacon_rx_failure_ntf)(uint32_t long_rd_id);
};

/* ============================================================================
 * INITIALIZATION
 * ========================================================================== */

/**
 * @brief Initialize the nRF modem library.
 *
 * Must be called before any other adapter function.
 *
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_init(void);

/**
 * @brief Register DECT MAC operation and notification callbacks.
 *
 * Must be called once after dect_adapter_init() and before any DECT operations.
 *
 * @param op_cbs  Operation completion callbacks
 * @param ntf_cbs Asynchronous notification callbacks
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_callbacks_set(
	const struct dect_adapter_op_callbacks *op_cbs,
	const struct dect_adapter_ntf_callbacks *ntf_cbs);

/* ============================================================================
 * SYSTEM CONTROL
 * ========================================================================== */

/**
 * @brief Initialize DECT system in MAC mode.
 *
 * Completion signaled via op_callbacks.systemmode.
 *
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_system_mode_set_mac(void);

/**
 * @brief Configure DECT control parameters.
 *
 * @param max_tx_power_dbm Maximum TX power in dBm
 * @param max_mcs          Maximum modulation/coding scheme (0-11)
 * @param rx_expected_rssi Expected RX RSSI level (dBm)
 * @param long_rd_id       Device long RD ID
 * @param carrier          Current carrier frequency (used to derive band group)
 * @param powersave        Enable power saving mode
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_control_configure(
	int max_tx_power_dbm,
	int max_mcs,
	int rx_expected_rssi,
	uint32_t long_rd_id,
	uint16_t carrier,
	bool powersave);

/**
 * @brief Set functional mode (activate/deactivate radio).
 *
 * Completion signaled via op_callbacks.functional_mode.
 *
 * @param activate true to activate, false to deactivate
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_functional_mode_set(bool activate);

/* ============================================================================
 * FT (FIXED TERMINAL) OPERATIONS
 * ========================================================================== */

/**
 * @brief Start RSSI scan on all channels in the band of the given carrier.
 *
 * Results reported via ntf_callbacks.rssi_scan_ntf per channel.
 * Completion signaled via op_callbacks.rssi_scan.
 *
 * @param carrier        Carrier frequency (used to select band)
 * @param threshold_low  Lower RSSI threshold in dBm (e.g., -95)
 * @param threshold_high Upper RSSI threshold in dBm (e.g., -70)
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_rssi_scan_start(
	uint16_t carrier,
	int threshold_low,
	int threshold_high);

/**
 * @brief Stop active RSSI scan.
 *
 * Completion signaled via op_callbacks.rssi_scan_stop.
 *
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_rssi_scan_stop(void);

/**
 * @brief Configure cluster beacon for FT and start beaconing.
 *
 * Completion signaled via op_callbacks.cluster_configure.
 *
 * @param channel               Carrier frequency channel
 * @param cluster_beacon_period Beacon period in ms (10, 50, 100, 500, 1000, ...)
 * @param network_id            Network identifier
 * @param tx_power_dbm          TX power in dBm
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_cluster_configure_ft(
	uint16_t channel,
	uint32_t cluster_beacon_period,
	uint32_t network_id,
	int tx_power_dbm,
	uint8_t rach_fill_percentage);

/**
 * @brief Configure network beacon for FT.
 *
 * Completion signaled via op_callbacks.network_beacon_configure.
 *
 * @param channel         Carrier frequency channel
 * @param nw_beacon_period Network beacon period in ms
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_network_beacon_configure_ft(
	uint16_t channel,
	uint32_t nw_beacon_period);

/**
 * @brief Select the smallest valid network beacon period >= cluster_period_ms.
 *
 * @param cluster_period_ms  Cluster beacon period in ms
 * @param network_period_ms  Output: recommended network beacon period in ms
 * @return 0 on success, -EINVAL if cluster_period_ms is out of supported range
 */
int dect_adapter_nw_period_from_cluster_period(
	uint32_t cluster_period_ms,
	uint32_t *network_period_ms);

/* ============================================================================
 * PT (PORTABLE TERMINAL) OPERATIONS
 * ========================================================================== */

/**
 * @brief Start network scan to find parent FT beacons.
 *
 * Completion signaled via op_callbacks.network_scan.
 *
 * @param channel            Carrier frequency channel to scan
 * @param scan_time_ms       Dwell time in ms
 * @param network_id_filter  Network ID to filter (0 = accept any)
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_network_scan_start(
	uint16_t channel,
	uint32_t scan_time_ms,
	uint32_t network_id_filter);

/**
 * @brief Stop active network scan.
 *
 * Completion signaled via op_callbacks.network_scan_stop.
 *
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_network_scan_stop(void);

/**
 * @brief Subscribe to cluster beacons from a discovered FT.
 *
 * @param channel               Carrier frequency channel
 * @param cluster_beacon_period Beacon period in ms
 * @param parent_long_rd_id     Long RD ID of parent FT
 * @param network_id            Network ID
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_cluster_beacon_receive_start(
	uint16_t channel,
	uint32_t cluster_beacon_period,
	uint32_t parent_long_rd_id,
	uint32_t network_id);

/**
 * @brief Stop cluster beacon subscription.
 *
 * Completion signaled via op_callbacks.cluster_beacon_receive_stop.
 *
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_cluster_beacon_receive_stop(void);

/* ============================================================================
 * ASSOCIATION & DATA TRANSFER (BOTH FT & PT)
 * ========================================================================== */

/**
 * @brief Request association with peer FT.
 *
 * Completion signaled via ntf_callbacks.association_ntf.
 *
 * @param peer_long_rd_id Long RD ID of peer FT
 * @param network_id      Network ID
 * @param flow_id         Flow ID (typically 1)
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_association_request(
	uint32_t peer_long_rd_id,
	uint32_t network_id);

/**
 * @brief Release an association with a peer (PT releases from FT, or FT releases a PT).
 *
 * Completion signaled via op_callbacks.association_release.
 *
 * @param peer_long_rd_id Long RD ID of peer to release
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_association_release(uint32_t peer_long_rd_id);

/**
 * @brief Send DLC data to an associated peer.
 *
 * Completion signaled via op_callbacks.dlc_data_tx.
 *
 * @param transaction_id  Caller-assigned ID for tracking completion
 * @param flow_id         Flow ID (typically 1)
 * @param peer_long_rd_id Long RD ID of destination
 * @param data            Pointer to data buffer
 * @param data_len        Length of data in bytes
 * @return 0 on success, negative error code on failure
 */
int dect_adapter_dlc_data_send(
	uint32_t transaction_id,
	uint8_t flow_id,
	uint32_t peer_long_rd_id,
	const void *data,
	size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* DECT_ADAPTER_H__ */
