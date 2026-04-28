/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/drivers/hwinfo.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/shell/shell.h>
#include <dk_buttons_and_leds.h>
#include "dect_adapter.h"

LOG_MODULE_REGISTER(app, CONFIG_LOG_DEFAULT_LEVEL);

#define APP_DATA_LEN_MAX 96
#define APP_FLOW_ID 1
#define APP_POLL_DELAY_MS 100
#define PT_BEACON_TABLE_SIZE 20

enum app_mode {
	APP_MODE_IDLE = 0,
	APP_MODE_FT,
	APP_MODE_PT,
};

enum wait_reason {
	WAIT_NONE = 0,
	WAIT_SYSTEMMODE,
	WAIT_CONFIGURE,
	WAIT_FUNCTIONAL,
	WAIT_CLUSTER_CONFIGURE,
	WAIT_NETWORK_BEACON_CONFIGURE,
	WAIT_NETWORK_SCAN,
	WAIT_RSSI_SCAN,
	WAIT_DLC_TX,
	WAIT_NETWORK_SCAN_STOP,
	WAIT_CLUSTER_BEACON_RECEIVE_STOP,
};

enum app_event_type {
	APP_EVT_NETWORK_BEACON = 0,
	APP_EVT_CLUSTER_BEACON,
	APP_EVT_ASSOCIATION_IND,
	APP_EVT_ASSOCIATION_RELEASE,
	APP_EVT_DLC_RX,
	APP_EVT_OP_NETWORK_SCAN,
	APP_EVT_OP_CLUSTER_BEACON_RECEIVE,
	APP_EVT_OP_CLUSTER_BEACON_RECEIVE_STOP,
	APP_EVT_OP_NETWORK_SCAN_STOP,
	APP_EVT_NTF_ASSOCIATION,
};

struct app_event {
	enum app_event_type type;
	union {
		struct {
			uint16_t channel;
			uint32_t network_id;
			uint32_t long_rd_id;
			uint32_t cluster_beacon_period_ms;
			int16_t rssi_dbm;
		} network_beacon;
		struct {
			uint16_t channel;
			uint32_t network_id;
			uint32_t long_rd_id;
			uint32_t cluster_beacon_period_ms;
			int16_t rssi_dbm;
		} cluster_beacon;
		struct {
			int status;
			uint32_t long_rd_id;
		} association_ind;
		struct {
			uint32_t long_rd_id;
		} association_release;
		struct {
			uint32_t long_rd_id;
			size_t len;
			char text[APP_DATA_LEN_MAX + 1];
		} dlc_rx;
		struct {
			int status;
		} op_network_scan;
		struct {
			int status;
		} op_cluster_beacon_receive;
		struct {
			int status;
		} op_cluster_beacon_receive_stop;
		struct {
			int status;
		} op_network_scan_stop;
		struct {
			int status;
			uint32_t long_rd_id;
		} ntf_association;
	};
};

/* Entry in the PT beacon discovery table. Populated by PT_SCAN. */
struct pt_beacon_entry {
	bool valid;
	uint16_t channel;
	uint32_t network_id;
	uint32_t long_rd_id;
	uint32_t cluster_beacon_period_ms;
	int16_t rssi_dbm;
};

static K_MUTEX_DEFINE(app_mutex);
static K_SEM_DEFINE(op_sem, 0, 1);
K_MSGQ_DEFINE(app_evt_msgq, sizeof(struct app_event), 16, 4);

static void led_work_handler(struct k_work *work);
static void pt_scan_work_handler(struct k_work *work);
static void pt_associate_work_handler(struct k_work *work);
static void pt_subscribe_timeout_handler(struct k_work *work);
static void pt_recovery_work_handler(struct k_work *work);
static void pt_resubscribe_work_handler(struct k_work *work);
static void pt_schedule_fast_recovery(const char *reason);
static int apply_control_configure(void);

static K_WORK_DELAYABLE_DEFINE(led_work, led_work_handler);
static K_WORK_DELAYABLE_DEFINE(pt_scan_work, pt_scan_work_handler);
static K_WORK_DELAYABLE_DEFINE(pt_associate_work, pt_associate_work_handler);
static K_WORK_DELAYABLE_DEFINE(pt_subscribe_timeout_work, pt_subscribe_timeout_handler);
static K_WORK_DELAYABLE_DEFINE(pt_recovery_work, pt_recovery_work_handler);
static K_WORK_DELAYABLE_DEFINE(pt_resubscribe_work, pt_resubscribe_work_handler);

static enum app_mode current_mode = APP_MODE_IDLE;
static uint16_t current_carrier = (CONFIG_APP_FIXED_CHANNEL != 0) ? CONFIG_APP_FIXED_CHANNEL : 1657;
static bool use_fixed_channel = (CONFIG_APP_FIXED_CHANNEL != 0);
static uint32_t pt_scan_time_ms = CONFIG_APP_DEFAULT_PT_SCAN_TIME_PER_CHANNEL_MS;
static uint32_t ft_period_ms = CONFIG_APP_DEFAULT_FT_PERIOD_MS;
static uint32_t nw_period_ms = CONFIG_APP_DEFAULT_NW_BEACON_PERIOD_MS;
static bool power_save_enabled;
static uint32_t device_long_rd_id;
static bool app_ready;
static bool ft_child_associated;
static bool pt_associated;
static bool pt_scan_in_progress;
static bool pt_association_pending;
static bool pt_network_found;
static bool ft_scan_result_valid;
static bool ft_post_scan; /* set after RSSI scan; configure_ft skips functional_mode bounce */
static bool pt_pending_subscribe; /* cmd_pt: waiting for beacon to sync timing before subscribe */
static uint32_t ft_child_long_rd_id;
static uint16_t ft_scan_best_channel = 1657;
static uint8_t ft_scan_best_busy = UINT8_MAX;
static uint32_t pt_parent_long_rd_id;
static uint32_t pt_network_id = CONFIG_APP_NETWORK_ID;
static uint16_t pt_parent_channel;
static uint32_t pt_parent_ft_period_ms; /* FT beacon period learned from beacon */
static uint8_t pt_association_retries;  /* failed attempts since last successful association */
static uint8_t pt_recovery_attempts;   /* consecutive auto-recovery cycles; reset on success */
static uint8_t pt_dlc_tx_fail_count;   /* consecutive DLC TX failures while associated */
static uint8_t ft_rach_fill_percentage = 100; /* RACH fill percentage (1-100) for FT cluster config */
static struct pt_beacon_entry pt_beacon_table[PT_BEACON_TABLE_SIZE];
static uint8_t pt_beacon_table_count;
static uint32_t tx_transaction_id = 1;
static uint32_t pending_tx_transaction_id;
static int scan_threshold_min = -85; /* dBm: carrier free if RSSI below this */
static int scan_threshold_max = -70; /* dBm: carrier busy if RSSI above this */
static volatile enum wait_reason current_wait = WAIT_NONE;
static volatile int wait_status;

static const char *mode_name(enum app_mode mode)
{
	switch (mode) {
	case APP_MODE_FT: return "FT";
	case APP_MODE_PT: return "PT";
	default:          return "IDLE";
	}
}

static void app_event_put(const struct app_event *evt)
{
	int err = k_msgq_put(&app_evt_msgq, evt, K_NO_WAIT);

	if (err != 0) {
		LOG_ERR("Dropping app event %d", evt->type);
	}
}

static void complete_wait(enum wait_reason reason, int status)
{
	if (current_wait != reason) {
		LOG_ERR("Received completion for wait reason %d, but current wait is %d", reason, current_wait);
		return;
	}

	wait_status = status;
	k_sem_give(&op_sem);
}

static void prepare_wait(enum wait_reason reason)
{
	while (k_sem_take(&op_sem, K_NO_WAIT) == 0) {
	}

	current_wait = reason;
	wait_status = -EINPROGRESS;
}

static void cancel_wait(enum wait_reason reason)
{
	if (current_wait == reason) {
		current_wait = WAIT_NONE;
	}
}

static int wait_for_prepared_operation(enum wait_reason reason, k_timeout_t timeout)
{
	if (current_wait != reason) {
		return -EINVAL;
	}

	if (k_sem_take(&op_sem, timeout) != 0) {
		current_wait = WAIT_NONE;
		return -ETIMEDOUT;
	}

	current_wait = WAIT_NONE;
	return wait_status;
}

static void led_apply(void)
{
	switch (current_mode) {
	case APP_MODE_FT:
		dk_set_leds(DK_ALL_LEDS_MSK);
		break;
	case APP_MODE_PT:
		k_work_reschedule(&led_work, K_NO_WAIT);
		break;
	default:
		dk_set_leds(0);
		break;
	}
}

static void reset_link_state(void)
{
	ft_child_associated = false;
	pt_associated = false;
	pt_scan_in_progress = false;
	pt_association_pending = false;
	pt_network_found = false;
	ft_child_long_rd_id = 0;
	pt_parent_long_rd_id = 0;
	pt_parent_channel = current_carrier;
	pt_network_id = CONFIG_APP_NETWORK_ID;
	pt_parent_ft_period_ms = 0;
	pt_association_retries = 0;
	pt_recovery_attempts = 0;
	pt_dlc_tx_fail_count = 0;
	pt_pending_subscribe = false;
	/* Note: pt_beacon_table is NOT cleared here; it persists across resets
	 * so that PT <channel> can be called after PT_SCAN without rescanning. */
}

static int stop_pt_activity(void)
{
	int err;

	if (pt_scan_in_progress) {
		prepare_wait(WAIT_NETWORK_SCAN_STOP);
		err = dect_adapter_network_scan_stop();
		if (err == 0) {
			(void)wait_for_prepared_operation(WAIT_NETWORK_SCAN_STOP, K_SECONDS(2));
		} else {
			cancel_wait(WAIT_NETWORK_SCAN_STOP);
		}
		pt_scan_in_progress = false;
	}

	k_work_cancel_delayable(&pt_scan_work);
	k_work_cancel_delayable(&pt_subscribe_timeout_work);
	k_work_cancel_delayable(&pt_recovery_work);
	return 0;
}

static int init_mac(bool reconfigure)
{
	int err;

	err = stop_pt_activity();
	if (err != 0) {
		LOG_ERR("init_mac: stop_pt_activity failed: %d", err);
		return err;
	}

	prepare_wait(WAIT_FUNCTIONAL);
	err = dect_adapter_functional_mode_set(false);
	if (err != 0) {
		cancel_wait(WAIT_FUNCTIONAL);
		LOG_ERR("init_mac: functional_mode_set(false) failed: %d", err);
		return err;
	}
	err = wait_for_prepared_operation(WAIT_FUNCTIONAL, K_SECONDS(1));
	if (err != 0) {
		LOG_ERR("init_mac: deactivate wait failed: %d", err);
		return err;
	}

	reset_link_state();
	ft_scan_result_valid = false;
	ft_scan_best_channel = current_carrier;
	ft_scan_best_busy = UINT8_MAX;

	if (reconfigure) {
		err = apply_control_configure();
		if (err != 0) {
			return err;
		}
	}

	prepare_wait(WAIT_FUNCTIONAL);
	err = dect_adapter_functional_mode_set(true);
	if (err != 0) {
		cancel_wait(WAIT_FUNCTIONAL);
		LOG_ERR("init_mac: functional_mode_set(true) failed: %d", err);
		return err;
	}

	err = wait_for_prepared_operation(WAIT_FUNCTIONAL, K_SECONDS(1));
	if (err != 0) {
		LOG_ERR("init_mac: activate wait failed: %d", err);
		return err;
	}

	return 0;
}

static int run_rssi_scan(void)
{
	int err;

	ft_scan_result_valid = false;
	ft_scan_best_channel = current_carrier;
	ft_scan_best_busy = UINT8_MAX;

	LOG_INF("RSSI scan starting (Band 1, all channels)...");
	prepare_wait(WAIT_RSSI_SCAN);
	err = dect_adapter_rssi_scan_start(current_carrier, scan_threshold_min, scan_threshold_max);
	if (err != 0) {
		cancel_wait(WAIT_RSSI_SCAN);
		LOG_ERR("RSSI scan submit failed: %d", err);
		return err;
	}

	err = wait_for_prepared_operation(WAIT_RSSI_SCAN, K_SECONDS(10));
	if (err != 0) {
		LOG_ERR("RSSI scan status: %d", err);
		return err;
	}

	if (ft_scan_result_valid) {
		if (!use_fixed_channel) {
			current_carrier = ft_scan_best_channel;
			LOG_INF("RSSI scan best: ch=%u busy=%u%% -> current_carrier set",
				ft_scan_best_channel, ft_scan_best_busy);
		} else {
			LOG_INF("RSSI scan best: ch=%u busy=%u%% (fixed channel %u, current_carrier unchanged)",
				ft_scan_best_channel, ft_scan_best_busy, current_carrier);
		}
	} else {
		LOG_WRN("RSSI scan: no valid channels found, current_carrier unchanged (%u)",
			current_carrier);
	}

	ft_post_scan = true;
	return 0;
}

static int configure_ft(void)
{
	int err;
	uint32_t nw_beacon_period_ms;

	if (ft_post_scan) {
		/* Modem is already activated and idle after RSSI scan.
		 * Skip the functional_mode bounce — the NCS driver goes directly
		 * from scan completion to cluster_configure. */
		ft_post_scan = false;
		(void)stop_pt_activity();
		reset_link_state();
		ft_scan_result_valid = false;
		ft_scan_best_channel = current_carrier;
		ft_scan_best_busy = UINT8_MAX;
	} else {
		err = init_mac(false);
		if (err != 0) {
			return err;
		}
	}

	LOG_INF("FT cluster configure: ch=%u nw=%u period=%u ms",
		current_carrier, CONFIG_APP_NETWORK_ID, ft_period_ms);
	prepare_wait(WAIT_CLUSTER_CONFIGURE);
	err = dect_adapter_cluster_configure_ft(
		current_carrier, ft_period_ms, CONFIG_APP_NETWORK_ID, CONFIG_APP_TX_POWER,
		ft_rach_fill_percentage);
	if (err != 0) {
		cancel_wait(WAIT_CLUSTER_CONFIGURE);
		LOG_ERR("FT cluster configure submit failed: %d", err);
		return err;
	}

	err = wait_for_prepared_operation(WAIT_CLUSTER_CONFIGURE, K_SECONDS(5));
	if (err != 0) {
		LOG_ERR("FT cluster configure status: %d", err);
		return err;
	}

	nw_beacon_period_ms = nw_period_ms;

	LOG_DBG("FT network beacon configure: ch=%u period=%u ms (cluster=%u ms)",
		current_carrier, nw_beacon_period_ms, ft_period_ms);
	prepare_wait(WAIT_NETWORK_BEACON_CONFIGURE);
	err = dect_adapter_network_beacon_configure_ft(current_carrier, nw_beacon_period_ms);
	if (err != 0) {
		cancel_wait(WAIT_NETWORK_BEACON_CONFIGURE);
		LOG_ERR("FT network beacon submit failed: %d", err);
		return err;
	}

	err = wait_for_prepared_operation(WAIT_NETWORK_BEACON_CONFIGURE, K_SECONDS(5));
	if (err != 0) {
		LOG_ERR("FT network beacon status: %d", err);
		return err;
	}

	current_mode = APP_MODE_FT;
	led_apply();
	LOG_DBG("FT beacon started: rd=%u ch=%u nw=%u period=%u ms",
		device_long_rd_id, current_carrier, CONFIG_APP_NETWORK_ID, ft_period_ms);
	return 0;
}

/* Store or update a beacon entry in the table, keyed by channel.
 * If the channel already exists, update it (latest RSSI). */
static void pt_table_store_beacon(uint16_t channel, uint32_t network_id,
				   uint32_t long_rd_id, uint32_t cluster_beacon_period_ms,
				   int16_t rssi_dbm)
{
	for (int i = 0; i < pt_beacon_table_count; i++) {
		if (pt_beacon_table[i].channel == channel) {
			pt_beacon_table[i].network_id = network_id;
			pt_beacon_table[i].long_rd_id = long_rd_id;
			pt_beacon_table[i].cluster_beacon_period_ms = cluster_beacon_period_ms;
			pt_beacon_table[i].rssi_dbm = rssi_dbm;
			return;
		}
	}

	if (pt_beacon_table_count < PT_BEACON_TABLE_SIZE) {
		struct pt_beacon_entry *e = &pt_beacon_table[pt_beacon_table_count++];

		e->valid = true;
		e->channel = channel;
		e->network_id = network_id;
		e->long_rd_id = long_rd_id;
		e->cluster_beacon_period_ms = cluster_beacon_period_ms;
		e->rssi_dbm = rssi_dbm;
	} else {
		LOG_WRN("Beacon table full (%d entries), ch=%u ignored", PT_BEACON_TABLE_SIZE, channel);
	}
}

/* Find a beacon table entry by channel. Returns NULL if not found. */
static const struct pt_beacon_entry *pt_table_find_by_channel(uint16_t channel)
{
	for (int i = 0; i < pt_beacon_table_count; i++) {
		if (pt_beacon_table[i].channel == channel) {
			return &pt_beacon_table[i];
		}
	}
	return NULL;
}

/* Start PT network scan mode. Clears beacon table and starts scan.
 * channel=0 scans all Band 1 channels; non-zero scans only that channel. */
static int start_pt_scan_mode(uint16_t channel)
{
	int err;
	uint16_t scan_channel;

	err = init_mac(true);
	if (err != 0) {
		return err;
	}

	current_mode = APP_MODE_PT;
	led_apply();

	/* Clear table for a fresh scan */
	memset(pt_beacon_table, 0, sizeof(pt_beacon_table));
	pt_beacon_table_count = 0;

	scan_channel = (channel != 0) ? channel : (use_fixed_channel ? current_carrier : 0);

	LOG_INF("PT network scan: channel=%u dwell=%u ms nw=%u",
		scan_channel, pt_scan_time_ms, CONFIG_APP_NETWORK_ID);
	err = dect_adapter_network_scan_start(scan_channel, pt_scan_time_ms,
					      CONFIG_APP_NETWORK_ID);
	if (err == 0) {
		pt_scan_in_progress = true;
	}

	return err;
}

static int start_pt_association(void)
{
	int err;

	if (pt_parent_long_rd_id == 0) {
		LOG_ERR("Cannot start association: FT long RD ID is 0");
		return -EINVAL;
	}

	LOG_INF("Starting PT association: rd=%u nw=%u",
		pt_parent_long_rd_id, pt_network_id);

	err = dect_adapter_association_request(pt_parent_long_rd_id, pt_network_id);
	if (err == 0) {
		pt_association_pending = true;
	}

	return err;
}

static int apply_control_configure(void)
{
	int err;

	prepare_wait(WAIT_CONFIGURE);
	err = dect_adapter_control_configure(
		CONFIG_APP_TX_POWER, CONFIG_APP_MCS, CONFIG_APP_RX_EXPECTED_RSSI,
		device_long_rd_id, current_carrier, power_save_enabled);
	if (err != 0) {
		cancel_wait(WAIT_CONFIGURE);
		LOG_ERR("apply_control_configure submit failed: %d", err);
		return err;
	}
	err = wait_for_prepared_operation(WAIT_CONFIGURE, K_SECONDS(5));
	if (err != 0) {
		LOG_ERR("apply_control_configure status: %d", err);
		return err;
	}
	return 0;
}

static int restart_current_mode(void)
{
	switch (current_mode) {
	case APP_MODE_FT:
		return configure_ft();
	case APP_MODE_PT:
		return start_pt_scan_mode(0);
	default:
		return init_mac(false);
	}
}

static int send_ascii(enum app_mode source_mode, const char *text)
{
	int err;
	uint32_t target_long_rd_id;
	char tx_buf[APP_DATA_LEN_MAX + 1];

	if (source_mode == APP_MODE_FT) {
		if (!ft_child_associated) {
			return -ENOTCONN;
		}
		target_long_rd_id = ft_child_long_rd_id;
	} else {
		if (!pt_associated) {
			return -ENOTCONN;
		}
		target_long_rd_id = pt_parent_long_rd_id;
	}

	snprintk(tx_buf, sizeof(tx_buf), "%s", text);
	printk("SEND MESSAGE: target_rd=%u len=%zu data=%s\n", target_long_rd_id, strlen(tx_buf) + 1, tx_buf);
	pending_tx_transaction_id = tx_transaction_id++;

	err = dect_adapter_dlc_data_send(
		pending_tx_transaction_id, APP_FLOW_ID,
		target_long_rd_id, tx_buf, strlen(tx_buf) + 1);
	if (err != 0) {
		return err;
	}

	printk("SEND queued: tx=%u\n", pending_tx_transaction_id);
	return 0;
}

/* ============================================================================
 * APP EVENT PROCESSING
 * ========================================================================== */

static void log_status(const char *tag, int status)
{
	if (status != 0) {
		LOG_ERR("%s status=%d", tag, status);
	}
}

static void process_network_beacon_event(const struct app_event *evt)
{
	if (current_mode == APP_MODE_PT && !pt_associated) {
		LOG_INF("Network beacon candidate: rd=%u ch=%u nw=%u period=%u ms rssi=%d dBm",
			evt->network_beacon.long_rd_id, evt->network_beacon.channel,
			evt->network_beacon.network_id, evt->network_beacon.cluster_beacon_period_ms,
			evt->network_beacon.rssi_dbm);
	}
}

static void process_cluster_beacon_event(const struct app_event *evt)
{
	if (current_mode != APP_MODE_PT) {
		return;
	}

	/* Resync path: cmd_pt did init_mac + network_scan to acquire timing.
	 * Now that we have a beacon from the target channel, stop the scan
	 * and proceed with cluster beacon subscribe. */
	k_mutex_lock(&app_mutex, K_FOREVER);
	bool do_subscribe = pt_pending_subscribe &&
			    (evt->cluster_beacon.channel == pt_parent_channel);
	if (do_subscribe) {
		pt_pending_subscribe = false;
	}
	k_mutex_unlock(&app_mutex);

	if (do_subscribe) {
		uint32_t period_ms = evt->cluster_beacon.cluster_beacon_period_ms;

		printk("FT found on ch=%u rd=%u — stopping scan and subscribing\n",
			evt->cluster_beacon.channel, evt->cluster_beacon.long_rd_id);
		/* stop_pt_activity() blocks until cb_op_network_scan_stop fires the semaphore
		 * from the modem callback thread — safe to call from the event loop. */
		stop_pt_activity();

		/* Update state from beacon (fast path launched with unknown rd/nw/period). */
		k_mutex_lock(&app_mutex, K_FOREVER);
		pt_parent_long_rd_id   = evt->cluster_beacon.long_rd_id;
		pt_network_id          = evt->cluster_beacon.network_id;
		pt_parent_ft_period_ms = period_ms;
		k_mutex_unlock(&app_mutex);

		(void)dect_adapter_cluster_beacon_receive_start(
			pt_parent_channel, period_ms,
			evt->cluster_beacon.long_rd_id, evt->cluster_beacon.network_id);
		k_work_reschedule(&pt_subscribe_timeout_work, K_MSEC(2 * period_ms));
		return;
	}

	/* Normal PT_SCAN path: store and print beacon */
	pt_table_store_beacon(
		evt->cluster_beacon.channel, evt->cluster_beacon.network_id,
		evt->cluster_beacon.long_rd_id, evt->cluster_beacon.cluster_beacon_period_ms,
		evt->cluster_beacon.rssi_dbm);

	if (!pt_associated) {
		printk("Beacon ch=%u rd=%u nw=%u period=%u ms rssi=%d dBm\n",
			evt->cluster_beacon.channel, evt->cluster_beacon.long_rd_id,
			evt->cluster_beacon.network_id, evt->cluster_beacon.cluster_beacon_period_ms,
			evt->cluster_beacon.rssi_dbm);
	}
}

/* FT side: a PT has associated with us */
static void process_association_ind_event(const struct app_event *evt)
{
	if (evt->association_ind.status == 0) {
		LOG_INF("process_association_ind_event status=%d rd=%u",
			evt->association_ind.status, evt->association_ind.long_rd_id);
	} else {
		LOG_ERR("process_association_ind_event status=%d rd=%u",
			evt->association_ind.status, evt->association_ind.long_rd_id);
	}
	k_mutex_lock(&app_mutex, K_FOREVER);
	ft_child_associated = true;
	ft_child_long_rd_id = evt->association_ind.long_rd_id;
	k_mutex_unlock(&app_mutex);
}

static void process_association_release_event(const struct app_event *evt)
{
	k_mutex_lock(&app_mutex, K_FOREVER);
	if (evt->association_release.long_rd_id == ft_child_long_rd_id) {
		ft_child_associated = false;
		ft_child_long_rd_id = 0;
	}
	if (evt->association_release.long_rd_id == pt_parent_long_rd_id) {
		pt_associated = false;
		pt_association_pending = false;
		pt_network_found = false;
		if (k_work_delayable_is_pending(&pt_resubscribe_work)) {
			/* beacon-failure path: keep pt_parent_long_rd_id so resubscribe can use it */
			printk("PT link released — resubscribing on ch=%u\n", pt_parent_channel);
		} else {
			pt_parent_long_rd_id = 0;
			printk("PT link dropped — scheduling auto-recovery on ch=%u\n", pt_parent_channel);
			pt_schedule_fast_recovery("link dropped");
		}
	}
	k_mutex_unlock(&app_mutex);
}

static void process_dlc_rx_event(const struct app_event *evt)
{
	const char *text = evt->dlc_rx.text;
	uint32_t long_rd_id = evt->dlc_rx.long_rd_id;

	printk("Received from rd=%u: %s\n", long_rd_id, text);
}

static void process_op_network_scan_event(const struct app_event *evt)
{
	int status = evt->op_network_scan.status;

	log_status("cb_op_network_scan", status);
	k_mutex_lock(&app_mutex, K_FOREVER);
	pt_scan_in_progress = false;
	bool was_resync = pt_pending_subscribe;
	if (was_resync) {
		/* Scan timed out before finding the FT beacon — clear pending flag */
		pt_pending_subscribe = false;
	}
	k_mutex_unlock(&app_mutex);

	if (was_resync) {
		printk("PT: resync scan timed out — FT not found on ch=%u. Check FT is running.\n",
			pt_parent_channel);
	} else {
		printk("PT_SCAN complete: %u beacon(s) found. Use PT <channel> to associate.\n",
			pt_beacon_table_count);
	}
}

static void process_op_cluster_beacon_receive_event(const struct app_event *evt)
{
	int status = evt->op_cluster_beacon_receive.status;

	log_status("cb_op_cluster_beacon_receive", status);
	k_work_cancel_delayable(&pt_subscribe_timeout_work);
	k_mutex_lock(&app_mutex, K_FOREVER);
	if (status != 0) {
		LOG_ERR("Cluster beacon subscribe failed");
	} else if (current_mode == APP_MODE_PT && !pt_associated && !pt_association_pending) {
		LOG_INF("Cluster beacon received, scheduling association rd=%u", pt_parent_long_rd_id);
		k_work_reschedule(&pt_associate_work, K_MSEC(1));
	}
	k_mutex_unlock(&app_mutex);
}

static void process_op_network_scan_stop_event(const struct app_event *evt)
{
	log_status("cb_op_network_scan_stop", evt->op_network_scan_stop.status);
	k_mutex_lock(&app_mutex, K_FOREVER);
	pt_scan_in_progress = false;
	k_mutex_unlock(&app_mutex);
}

static void process_op_cluster_beacon_receive_stop_event(const struct app_event *evt)
{
	int status = evt->op_cluster_beacon_receive_stop.status;

	if (status != 0) {
		LOG_ERR("cb_op_cluster_beacon_receive_stop status=%d", status);
	} else {
		LOG_DBG("cb_op_cluster_beacon_receive_stop status=%d", status);
	}
	complete_wait(WAIT_CLUSTER_BEACON_RECEIVE_STOP, status);
}

static void process_ntf_association_event(const struct app_event *evt)
{
	int status = evt->ntf_association.status;
	uint32_t long_rd_id = evt->ntf_association.long_rd_id;

	if (status == 0) {
		LOG_INF("cb_ntf_association status=%d rd=%u", status, long_rd_id);
		k_mutex_lock(&app_mutex, K_FOREVER);
		pt_associated = true;
		pt_association_pending = false;
		pt_association_retries = 0;
		pt_recovery_attempts = 0;
		pt_dlc_tx_fail_count = 0;
		pt_parent_long_rd_id = long_rd_id;
		k_mutex_unlock(&app_mutex);
		printk("PT associated with FT rd=%u\n", long_rd_id);
	} else {
		LOG_ERR("cb_ntf_association status=%d rd=%u", status, long_rd_id);
		k_mutex_lock(&app_mutex, K_FOREVER);
		pt_association_pending = false;

		if (status == 8) {
			/* NO_RESPONSE: FT did not respond. Retry automatically up to 10x. */
			pt_association_retries++;
			if (pt_association_retries >= 10) {
				LOG_WRN("PT association: 10 retries exhausted (rd=%u) — triggering recovery",
					long_rd_id);
				pt_association_retries = 0;
				pt_schedule_fast_recovery("association NO_RESPONSE exhausted");
			} else {
				uint32_t retry_ms = (pt_parent_ft_period_ms > 0)
					? 5 * pt_parent_ft_period_ms : 500;
				LOG_WRN("PT association NO_RESPONSE (status=8) rd=%u, retry %u/10 in %u ms",
					long_rd_id, pt_association_retries, retry_ms);
				k_work_reschedule(&pt_associate_work, K_MSEC(retry_ms));
			}
		} else {
			LOG_ERR("PT association failed: status=%d rd=%u — triggering recovery",
				status, long_rd_id);
			pt_association_retries = 0;
			pt_schedule_fast_recovery("association failed");
		}
		k_mutex_unlock(&app_mutex);
	}
}

static void process_app_event(const struct app_event *evt)
{
	switch (evt->type) {
	case APP_EVT_NETWORK_BEACON:
		process_network_beacon_event(evt);
		break;
	case APP_EVT_CLUSTER_BEACON:
		process_cluster_beacon_event(evt);
		break;
	case APP_EVT_ASSOCIATION_IND:
		process_association_ind_event(evt);
		break;
	case APP_EVT_ASSOCIATION_RELEASE:
		process_association_release_event(evt);
		break;
	case APP_EVT_DLC_RX:
		process_dlc_rx_event(evt);
		break;
	case APP_EVT_OP_NETWORK_SCAN:
		process_op_network_scan_event(evt);
		break;
	case APP_EVT_OP_CLUSTER_BEACON_RECEIVE:
		process_op_cluster_beacon_receive_event(evt);
		break;
	case APP_EVT_OP_CLUSTER_BEACON_RECEIVE_STOP:
		process_op_cluster_beacon_receive_stop_event(evt);
		break;
	case APP_EVT_OP_NETWORK_SCAN_STOP:
		process_op_network_scan_stop_event(evt);
		break;
	case APP_EVT_NTF_ASSOCIATION:
		process_ntf_association_event(evt);
		break;
	default:
		break;
	}
}

/* ============================================================================
 * WORK HANDLERS
 * ========================================================================== */

static void led_work_handler(struct k_work *work)
{
	static bool on;

	ARG_UNUSED(work);
	if (current_mode == APP_MODE_PT) {
		on = !on;
		dk_set_leds(on ? DK_ALL_LEDS_MSK : 0);
		k_work_reschedule(&led_work, K_MSEC(300));
	} else if (current_mode == APP_MODE_FT) {
		on = true;
		dk_set_leds(DK_ALL_LEDS_MSK);
	} else {
		on = false;
		dk_set_leds(0);
	}
}

static void pt_associate_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	k_mutex_lock(&app_mutex, K_FOREVER);
	if (current_mode != APP_MODE_PT || pt_associated || pt_association_pending) {
		k_mutex_unlock(&app_mutex);
		return;
	}
	LOG_INF("PT associate work: retrying association rd=%u", pt_parent_long_rd_id);
	if (start_pt_association() != 0) {
		LOG_ERR("PT association retry failed — run PT <channel> to restart");
	}
	k_mutex_unlock(&app_mutex);
}

/* Kept for k_work_cancel_delayable() in stop_pt_activity(). */
static void pt_scan_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
}

static void pt_resubscribe_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	k_mutex_lock(&app_mutex, K_FOREVER);
	if (current_mode != APP_MODE_PT || pt_associated) {
		k_mutex_unlock(&app_mutex);
		return;
	}
	uint16_t ch     = pt_parent_channel;
	uint32_t period = pt_parent_ft_period_ms;
	uint32_t rd     = pt_parent_long_rd_id;
	uint32_t nw     = pt_network_id;
	k_mutex_unlock(&app_mutex);

	if (period == 0 || rd == 0) {
		LOG_WRN("PT resubscribe: missing period or rd — falling back to full recovery");
		k_mutex_lock(&app_mutex, K_FOREVER);
		pt_parent_long_rd_id = 0;
		pt_schedule_fast_recovery("resubscribe missing state");
		k_mutex_unlock(&app_mutex);
		return;
	}

	printk("PT resubscribe: ch=%u rd=%u period=%u ms\n", ch, rd, period);
	int err = dect_adapter_cluster_beacon_receive_start(ch, period, rd, nw);
	if (err != 0) {
		LOG_ERR("PT resubscribe: cluster_beacon_receive_start failed: %d", err);
		k_mutex_lock(&app_mutex, K_FOREVER);
		pt_parent_long_rd_id = 0;
		pt_schedule_fast_recovery("resubscribe start failed");
		k_mutex_unlock(&app_mutex);
		return;
	}
	k_work_reschedule(&pt_subscribe_timeout_work, K_MSEC(2 * period));
}

static void pt_schedule_fast_recovery(const char *reason)
{
	k_msleep(rand() % 10 + 1);
	/* Must be called with app_mutex held. */
	if (pt_parent_channel == 0) {
		LOG_WRN("PT recovery: no channel known, cannot recover");
		return;
	}
	if (pt_recovery_attempts >= 5) {
		printk("PT: recovery exhausted after 5 attempts on ch=%u — run PT <channel> manually\n",
			pt_parent_channel);
		pt_recovery_attempts = 0;
		return;
	}
	pt_recovery_attempts++;
	printk("PT: auto-recovery %u/5 on ch=%u (%s)\n",
		pt_recovery_attempts, pt_parent_channel, reason);
	k_work_reschedule(&pt_recovery_work, K_MSEC(100));
}

static void pt_subscribe_timeout_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	k_mutex_lock(&app_mutex, K_FOREVER);
	bool timed_out = (current_mode == APP_MODE_PT && !pt_associated && !pt_association_pending);
	uint16_t ch = pt_parent_channel;
	k_mutex_unlock(&app_mutex);

	if (timed_out) {
		dect_adapter_cluster_beacon_receive_stop();
		printk("PT: no beacon received on ch=%u\n", ch);
		k_mutex_lock(&app_mutex, K_FOREVER);
		pt_schedule_fast_recovery("subscribe timeout");
		k_mutex_unlock(&app_mutex);
	}
}

static void pt_recovery_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	k_mutex_lock(&app_mutex, K_FOREVER);
	if (current_mode != APP_MODE_PT || pt_associated) {
		k_mutex_unlock(&app_mutex);
		return;
	}
	uint16_t ch = pt_parent_channel;
	uint32_t nw = CONFIG_APP_NETWORK_ID;
	k_mutex_unlock(&app_mutex);

	LOG_INF("PT recovery: init_mac + scan ch=%u", ch);

	stop_pt_activity();

	if (init_mac(true) != 0) {
		LOG_ERR("PT recovery: init_mac failed");
		k_mutex_lock(&app_mutex, K_FOREVER);
		pt_schedule_fast_recovery("init_mac failed");
		k_mutex_unlock(&app_mutex);
		return;
	}

	k_mutex_lock(&app_mutex, K_FOREVER);
	current_mode           = APP_MODE_PT;
	pt_parent_channel      = ch;
	pt_association_pending = false;
	pt_association_retries = 0;
	pt_dlc_tx_fail_count   = 0;
	pt_pending_subscribe   = true;
	pt_scan_in_progress    = true;
	k_mutex_unlock(&app_mutex);

	led_apply();

	if (dect_adapter_network_scan_start(ch, pt_scan_time_ms, nw) != 0) {
		LOG_ERR("PT recovery: network_scan_start failed");
		k_mutex_lock(&app_mutex, K_FOREVER);
		pt_pending_subscribe = false;
		pt_scan_in_progress  = false;
		pt_schedule_fast_recovery("scan start failed");
		k_mutex_unlock(&app_mutex);
	}
}

/* ============================================================================
 * DECT ADAPTER CALLBACKS
 * ========================================================================== */

static void cb_op_functional_mode(int status)
{
	log_status("cb_op_functional_mode", status);
	complete_wait(WAIT_FUNCTIONAL, status);
}

static void cb_op_configure(int status)
{
	log_status("cb_op_configure", status);
	complete_wait(WAIT_CONFIGURE, status);
}

static void cb_op_systemmode(int status)
{
	log_status("cb_op_systemmode", status);
	complete_wait(WAIT_SYSTEMMODE, status);
}

static void cb_op_cluster_configure(int status)
{
	log_status("cb_op_cluster_configure", status);
	complete_wait(WAIT_CLUSTER_CONFIGURE, status);
}

static void cb_op_cluster_beacon_receive(int status)
{
	struct app_event evt = {
		.type = APP_EVT_OP_CLUSTER_BEACON_RECEIVE,
		.op_cluster_beacon_receive = { .status = status },
	};

	app_event_put(&evt);
}

static void cb_op_cluster_beacon_receive_stop(int status)
{
	struct app_event evt = {
		.type = APP_EVT_OP_CLUSTER_BEACON_RECEIVE_STOP,
		.op_cluster_beacon_receive_stop = { .status = status },
	};

	LOG_DBG("cb_op_cluster_beacon_receive_stop status=%d", status);
	app_event_put(&evt);
	complete_wait(WAIT_CLUSTER_BEACON_RECEIVE_STOP, status);
}

static void cb_op_network_beacon_configure(int status)
{
	log_status("cb_op_network_beacon_configure", status);
	complete_wait(WAIT_NETWORK_BEACON_CONFIGURE, status);
}

static void cb_op_network_scan(int status)
{
	struct app_event evt = {
		.type = APP_EVT_OP_NETWORK_SCAN,
		.op_network_scan = { .status = status },
	};

	app_event_put(&evt);
}

static void cb_op_network_scan_stop(int status)
{
	struct app_event evt = {
		.type = APP_EVT_OP_NETWORK_SCAN_STOP,
		.op_network_scan_stop = { .status = status },
	};

	app_event_put(&evt);
	complete_wait(WAIT_NETWORK_SCAN_STOP, status);
}

static void cb_op_rssi_scan(int status)
{
	log_status("cb_op_rssi_scan", status);
	complete_wait(WAIT_RSSI_SCAN, status);
}

static void cb_op_dlc_data_tx(int status, uint32_t transaction_id)
{
	if (status == 0) {
		LOG_INF("TX done: tx=%u", transaction_id);
	} else {
		LOG_WRN("TX failed: tx=%u status=%d", transaction_id, status);
	}
}

/* PT side: our association with FT completed */
static void cb_ntf_association(int status, uint32_t long_rd_id)
{
	struct app_event evt = {
		.type = APP_EVT_NTF_ASSOCIATION,
		.ntf_association = { .status = status, .long_rd_id = long_rd_id },
	};

	app_event_put(&evt);
}

static void cb_ntf_association_release(uint32_t long_rd_id)
{
	LOG_WRN("association_release: rd=%u\n", long_rd_id);
	struct app_event evt = {
		.type = APP_EVT_ASSOCIATION_RELEASE,
		.association_release = {
			.long_rd_id = long_rd_id,
		},
	};

	app_event_put(&evt);
}

/* FT side: a PT has associated with us */
static void cb_ntf_association_ind(int status, uint32_t long_rd_id)
{
	if (status == 0) {
		LOG_INF("cb_ntf_association_ind status=%d rd=%u", status, long_rd_id);
	} else {
		LOG_ERR("cb_ntf_association_ind status=%d rd=%u", status, long_rd_id);
	}
	struct app_event evt = {
		.type = APP_EVT_ASSOCIATION_IND,
		.association_ind = {
			.status = status,
			.long_rd_id = long_rd_id,
		},
	};
	app_event_put(&evt);
}

static void cb_ntf_rssi_scan(uint16_t channel, uint8_t busy_percentage,
			     size_t free_slots, size_t possible_slots, size_t total_slots)
{
	/* ETSI EN 301 406-2: band 1 harmonized standard uses only odd channels */
	if (channel % 2 == 0) {
		return;
	}
	LOG_INF("  ch=%u busy=%u%% free=%zu possible=%zu/%zu slots", channel, busy_percentage,
		free_slots, possible_slots, total_slots);
	if (!ft_scan_result_valid || busy_percentage < ft_scan_best_busy) {
		ft_scan_result_valid = true;
		ft_scan_best_channel = channel;
		ft_scan_best_busy = busy_percentage;
	}
}

static void cb_ntf_cluster_beacon(uint16_t channel, uint32_t network_id, uint32_t long_rd_id,
				  uint32_t cluster_beacon_period_ms, int16_t rssi_dbm)
{
	struct app_event evt = {
		.type = APP_EVT_CLUSTER_BEACON,
		.cluster_beacon = {
			.channel = channel,
			.network_id = network_id,
			.long_rd_id = long_rd_id,
			.cluster_beacon_period_ms = cluster_beacon_period_ms,
			.rssi_dbm = rssi_dbm,
		},
	};

	app_event_put(&evt);
}

static void cb_ntf_network_beacon(uint16_t channel, uint32_t network_id, uint32_t long_rd_id,
				  uint32_t cluster_beacon_period_ms, int16_t rssi_dbm)
{
	struct app_event evt = {
		.type = APP_EVT_NETWORK_BEACON,
		.network_beacon = {
			.channel = channel,
			.network_id = network_id,
			.long_rd_id = long_rd_id,
			.cluster_beacon_period_ms = cluster_beacon_period_ms,
			.rssi_dbm = rssi_dbm,
		},
	};

	app_event_put(&evt);
}

static void cb_ntf_dlc_data_rx(uint32_t long_rd_id, const void *data, size_t data_len)
{
	struct app_event evt = {
		.type = APP_EVT_DLC_RX,
		.dlc_rx = {
			.long_rd_id = long_rd_id,
			.len = MIN(data_len, (size_t)APP_DATA_LEN_MAX),
		},
	};

	memcpy(evt.dlc_rx.text, data, evt.dlc_rx.len);
	evt.dlc_rx.text[evt.dlc_rx.len] = '\0';
	printk("DLC RX ntf: rd=%u len=%zu data=%s\n", long_rd_id, data_len, evt.dlc_rx.text);
	app_event_put(&evt);
}

static void cb_ntf_cluster_beacon_rx_failure(uint32_t long_rd_id)
{
	LOG_WRN("cluster_beacon_rx_failure: rd=%u — releasing and resubscribing", long_rd_id);
	k_mutex_lock(&app_mutex, K_FOREVER);
	pt_associated = false;
	pt_association_pending = false;
	k_mutex_unlock(&app_mutex);
	(void)dect_adapter_association_release(long_rd_id);
	//long delay here for manual FT reset and restart
	k_work_reschedule(&pt_resubscribe_work, K_MSEC(5000));
}

static const struct dect_adapter_op_callbacks app_op_callbacks = {
	.functional_mode             = cb_op_functional_mode,
	.configure                   = cb_op_configure,
	.systemmode                  = cb_op_systemmode,
	.cluster_configure           = cb_op_cluster_configure,
	.cluster_beacon_receive      = cb_op_cluster_beacon_receive,
	.cluster_beacon_receive_stop = cb_op_cluster_beacon_receive_stop,
	.network_beacon_configure    = cb_op_network_beacon_configure,
	.network_scan                = cb_op_network_scan,
	.network_scan_stop           = cb_op_network_scan_stop,
	.rssi_scan                   = cb_op_rssi_scan,
	.dlc_data_tx                 = cb_op_dlc_data_tx,
};

static const struct dect_adapter_ntf_callbacks app_ntf_callbacks = {
	.association_ntf                  = cb_ntf_association,
	.association_release_ntf          = cb_ntf_association_release,
	.association_ind_ntf              = cb_ntf_association_ind,
	.rssi_scan_ntf                    = cb_ntf_rssi_scan,
	.cluster_beacon_ntf               = cb_ntf_cluster_beacon,
	.network_beacon_ntf               = cb_ntf_network_beacon,
	.dlc_data_rx_ntf                  = cb_ntf_dlc_data_rx,
	.cluster_beacon_rx_failure_ntf    = cb_ntf_cluster_beacon_rx_failure,
};

/* ============================================================================
 * SHELL COMMANDS
 * ========================================================================== */

static int cmd_send(const struct shell *shell, size_t argc, char **argv)
{
	int err;
	char text[APP_DATA_LEN_MAX + 1];
	size_t pos = 0;
	enum app_mode source_mode;

	for (size_t i = 1; i < argc; i++) {
		int written = snprintk(text + pos, sizeof(text) - pos, "%s%s",
				       i > 1 ? " " : "", argv[i]);
		if (written < 0 || written >= (int)(sizeof(text) - pos)) {
			shell_error(shell, "Message too long");
			return -EINVAL;
		}
		pos += written;
	}

	k_mutex_lock(&app_mutex, K_FOREVER);
	source_mode = current_mode == APP_MODE_FT ? APP_MODE_FT : APP_MODE_PT;
	err = send_ascii(source_mode, text);
	if (source_mode == APP_MODE_PT) {
		if (err == 0) {
			pt_dlc_tx_fail_count = 0;
		} else if (pt_associated) {
			pt_dlc_tx_fail_count++;
			if (pt_dlc_tx_fail_count >= 3) {
				printk("PT: DLC TX failed %u times — triggering recovery\n",
					pt_dlc_tx_fail_count);
				pt_dlc_tx_fail_count = 0;
				pt_associated = false;
				pt_schedule_fast_recovery("DLC TX repeated failure");
			}
		}
	}
	k_mutex_unlock(&app_mutex);
	if (err != 0) {
		shell_error(shell, "SEND failed: %d", err);
		return err;
	}

	shell_print(shell, "Sent from %s: %s", mode_name(source_mode), text);
	return 0;
}

static int cmd_scan(const struct shell *shell, size_t argc, char **argv)
{
	int err;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (!app_ready) {
		shell_error(shell, "Device not ready");
		return -ENODEV;
	}

	err = run_rssi_scan();
	if (err != 0) {
		shell_error(shell, "RSSI scan failed: %d", err);
		return err;
	}

	if (ft_scan_result_valid) {
		if (use_fixed_channel) {
			shell_print(shell, "Best channel: %u (busy=%u%%) [fixed channel %u active, informational only]",
				    ft_scan_best_channel, ft_scan_best_busy, current_carrier);
		} else {
			shell_print(shell, "Best channel: %u (busy=%u%%) -> use FT %u to beacon",
				    ft_scan_best_channel, ft_scan_best_busy, ft_scan_best_channel);
		}
	} else {
		shell_print(shell, "Scan complete: no valid result, current_carrier=%u", current_carrier);
	}

	return 0;
}

static int cmd_ft(const struct shell *shell, size_t argc, char **argv)
{
	int err;

	if (argc >= 2) {
		long carrier_val = strtol(argv[1], NULL, 10);

		if (carrier_val <= 0 || carrier_val > UINT16_MAX) {
			shell_error(shell, "Carrier must be between 1 and %u", UINT16_MAX);
			return -EINVAL;
		}
		current_carrier = (uint16_t)carrier_val;
		shell_print(shell, "FT: using carrier %u", current_carrier);
	} else if (use_fixed_channel) {
		shell_print(shell, "FT: using fixed channel %u", current_carrier);
	} else {
		shell_print(shell, "FT: using current_carrier %u (run SCAN to update)", current_carrier);
	}

	err = configure_ft();
	if (err != 0) {
		shell_error(shell, "FT failed: %d", err);
		return err;
	}

	shell_print(shell, "FT beaconing on ch=%u period=%u ms", current_carrier, ft_period_ms);
	return 0;
}

static int cmd_period(const struct shell *shell, size_t argc, char **argv)
{
	int err = 0;
	bool restart_ft;
	long value = strtol(argv[1], NULL, 10);

	ARG_UNUSED(argc);

	if (value < 50 || value > 32000) {
		shell_error(shell, "PERIOD must be between 50 and 32000 ms");
		return -EINVAL;
	}

	k_mutex_lock(&app_mutex, K_FOREVER);
	ft_period_ms = (uint32_t)value;
	restart_ft = (current_mode == APP_MODE_FT);
	k_mutex_unlock(&app_mutex);
	pt_scan_time_ms = 2 * ft_period_ms; /* PT scan time should be at least 2 beacon periods */
	if (restart_ft) {
		err = configure_ft();
	}

	if (err != 0) {
		shell_error(shell, "PERIOD update failed: %d", err);
		return err;
	}

	shell_print(shell, "FT beacon period set to %u ms, scan time to 2x %u ms", ft_period_ms, pt_scan_time_ms);
	return 0;
}

/* PT_SCAN [channel] — scan for FT beacons, populate discovery table, no auto-association. */
static int cmd_pt_scan(const struct shell *shell, size_t argc, char **argv)
{
	int err;
	uint16_t channel = 0; /* 0 = all Band 1 channels */

	if (!app_ready) {
		shell_error(shell, "Device not ready");
		return -ENODEV;
	}

	if (argc >= 2) {
		long ch = strtol(argv[1], NULL, 10);

		if (ch <= 0 || ch > UINT16_MAX) {
			shell_error(shell, "Channel must be between 1 and %u", UINT16_MAX);
			return -EINVAL;
		}
		channel = (uint16_t)ch;
	}

	k_mutex_lock(&app_mutex, K_FOREVER);
	err = start_pt_scan_mode(channel);
	k_mutex_unlock(&app_mutex);

	if (err != 0) {
		shell_error(shell, "PT_SCAN failed: %d", err);
		return err;
	}

	if (channel == 0) {
		shell_print(shell, "PT scanning all channels (%u ms/ch). Beacons printed as received.", pt_scan_time_ms);
	} else {
		shell_print(shell, "PT scanning ch=%u (%u ms). Beacons printed as received.", channel, pt_scan_time_ms);
	}
	shell_print(shell, "When done, use PT <channel> to associate.");
	return 0;
}

/* PT <channel> — associate with FT on <channel>.
 * Fast path (no prior PT_SCAN): init_mac + network_scan to find the FT, then
 * auto-subscribe and associate.
 * Slow path (after PT_SCAN): uses stored beacon table values to subscribe directly. */
static int cmd_pt(const struct shell *shell, size_t argc, char **argv)
{
	int err;
	uint16_t channel;
	uint32_t rd_id, nw_id, period_ms;

	if (argc < 2) {
		shell_error(shell, "Usage: PT <channel>");
		return -EINVAL;
	}

	long ch = strtol(argv[1], NULL, 10);

	if (ch <= 0 || ch > UINT16_MAX) {
		shell_error(shell, "Channel must be between 1 and %u", UINT16_MAX);
		return -EINVAL;
	}
	channel = (uint16_t)ch;

	/* Look up the channel in the scan table */
	k_mutex_lock(&app_mutex, K_FOREVER);
	const struct pt_beacon_entry *entry = pt_table_find_by_channel(channel);

	if (entry == NULL) {
		k_mutex_unlock(&app_mutex);

		/* Fast path: no prior PT_SCAN for this channel.
		 * Scan the channel to find the FT, then auto-subscribe and associate.
		 * rd_id and period are unknown until the first beacon is received;
		 * process_cluster_beacon_event() fills them in before subscribing. */
		shell_print(shell, "PT fast: ch=%u scanning for FT...", channel);

		err = init_mac(true);
		if (err != 0) {
			shell_error(shell, "MAC init failed: %d", err);
			return err;
		}

		k_mutex_lock(&app_mutex, K_FOREVER);
		current_mode           = APP_MODE_PT;
		pt_parent_channel      = channel;
		pt_parent_long_rd_id   = 0;
		pt_network_id          = CONFIG_APP_NETWORK_ID;
		pt_parent_ft_period_ms = ft_period_ms;
		pt_association_pending = false;
		pt_association_retries = 0;
		pt_pending_subscribe   = true;
		pt_scan_in_progress    = true;
		k_mutex_unlock(&app_mutex);

		led_apply();

		err = dect_adapter_network_scan_start(channel, pt_scan_time_ms,
						      CONFIG_APP_NETWORK_ID);
		if (err != 0) {
			k_mutex_lock(&app_mutex, K_FOREVER);
			pt_pending_subscribe = false;
			pt_scan_in_progress  = false;
			k_mutex_unlock(&app_mutex);
			shell_error(shell, "Network scan failed: %d", err);
			return err;
		}
		shell_print(shell, "Scanning ch=%u — will subscribe and associate on first beacon",
			    channel);
		return 0;
	}

	rd_id     = entry->long_rd_id;
	nw_id     = entry->network_id;
	period_ms = entry->cluster_beacon_period_ms;
	k_mutex_unlock(&app_mutex);

	/* Determine whether the modem already has timing context from a recent PT_SCAN.
	 * cluster_beacon_receive_start requires the modem to know the FT's beacon timing.
	 * init_mac(true) resets the modem and loses that sync, so we avoid it when
	 * the modem is already active in PT mode (scan just completed). */
	k_mutex_lock(&app_mutex, K_FOREVER);
	bool modem_synced = (current_mode == APP_MODE_PT && !pt_scan_in_progress && !pt_associated);
	k_mutex_unlock(&app_mutex);

	if (modem_synced) {
		/* Fast path: modem active with timing from PT_SCAN — subscribe directly. */
		shell_print(shell, "Associating: ch=%u rd=%u nw=%u", channel, rd_id, nw_id);

		k_mutex_lock(&app_mutex, K_FOREVER);
		current_mode           = APP_MODE_PT;
		pt_parent_long_rd_id   = rd_id;
		pt_network_id          = nw_id;
		pt_parent_channel      = channel;
		pt_parent_ft_period_ms = period_ms;
		pt_association_pending = false;
		pt_association_retries = 0;
		k_mutex_unlock(&app_mutex);

		led_apply();

		err = dect_adapter_cluster_beacon_receive_start(channel, period_ms, rd_id, nw_id);
		if (err != 0) {
			shell_error(shell, "Cluster beacon subscribe failed: %d", err);
			return err;
		}
		shell_print(shell, "Subscribing to cluster beacon on ch=%u — will associate with rd=%u when RA schedule is known",
			    channel, rd_id);
	} else {
		/* Cold path: modem not active (after STOP or first use).
		 * Do init_mac + brief network_scan to re-acquire FT timing,
		 * then process_cluster_beacon_event() will call cluster_beacon_receive_start. */
		shell_print(shell, "Syncing to FT: ch=%u rd=%u nw=%u", channel, rd_id, nw_id);

		err = init_mac(true);
		if (err != 0) {
			shell_error(shell, "MAC init failed: %d", err);
			return err;
		}

		k_mutex_lock(&app_mutex, K_FOREVER);
		current_mode           = APP_MODE_PT;
		pt_parent_long_rd_id   = rd_id;
		pt_network_id          = nw_id;
		pt_parent_channel      = channel;
		pt_parent_ft_period_ms = period_ms;
		pt_association_pending = false;
		pt_association_retries = 0;
		pt_pending_subscribe   = true;
		pt_scan_in_progress    = true;
		k_mutex_unlock(&app_mutex);

		led_apply();

		err = dect_adapter_network_scan_start(channel, pt_scan_time_ms, nw_id);
		if (err != 0) {
			k_mutex_lock(&app_mutex, K_FOREVER);
			pt_pending_subscribe = false;
			pt_scan_in_progress  = false;
			k_mutex_unlock(&app_mutex);
			shell_error(shell, "Resync scan failed: %d", err);
			return err;
		}
		shell_print(shell, "Scanning ch=%u to sync with FT (rd=%u) — will subscribe and associate automatically",
			    channel, rd_id);
	}
	return 0;
}

static int cmd_status(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	k_mutex_lock(&app_mutex, K_FOREVER);
	shell_print(shell, "Mode: %s", mode_name(current_mode));
	if (current_mode == APP_MODE_FT) {
		shell_print(shell, "FT beacon period: %u ms", ft_period_ms);
		shell_print(shell, "FT RACH fill: %u%%", ft_rach_fill_percentage);
		shell_print(shell, "FT child associated: %s (rd=%u)",
			ft_child_associated ? "yes" : "no", ft_child_long_rd_id);
	}
	if (current_mode == APP_MODE_PT) {
		shell_print(shell, "PT associated: %s", pt_associated ? "yes" : "no");
		shell_print(shell, "PT scan time: %u ms", pt_scan_time_ms);
		if (pt_associated) {
			shell_print(shell, "PT parent channel: %u", pt_parent_channel);
			shell_print(shell, "PT parent long RD ID: %u", pt_parent_long_rd_id);
		}
	}
	shell_print(shell, "Beacon table: %u entr%s", pt_beacon_table_count,
		    pt_beacon_table_count == 1 ? "y" : "ies");
	for (int i = 0; i < pt_beacon_table_count; i++) {
		const struct pt_beacon_entry *e = &pt_beacon_table[i];

		shell_print(shell, "  [%d] ch=%u rd=%u nw=%u period=%u ms rssi=%d dBm",
			    i, e->channel, e->long_rd_id, e->network_id,
			    e->cluster_beacon_period_ms, e->rssi_dbm);
	}
	shell_print(shell, "Power save: %s", power_save_enabled ? "enabled" : "disabled");
	k_mutex_unlock(&app_mutex);

	return 0;
}

static int cmd_powersave(const struct shell *shell, size_t argc, char **argv)
{
	int err = 0;
	bool restart_mode;
	long value = strtol(argv[1], NULL, 10);

	ARG_UNUSED(argc);

	if (value != 0 && value != 1) {
		shell_error(shell, "POWERSAVE must be 0 (disabled) or 1 (enabled)");
		return -EINVAL;
	}

	k_mutex_lock(&app_mutex, K_FOREVER);
	power_save_enabled = (value == 1);
	restart_mode = (current_mode == APP_MODE_PT || current_mode == APP_MODE_FT);
	k_mutex_unlock(&app_mutex);

	if (restart_mode) {
		err = restart_current_mode();
	}

	if (err != 0) {
		shell_error(shell, "POWERSAVE update failed: %d", err);
		return err;
	}

	shell_print(shell, "Power save %s", power_save_enabled ? "enabled" : "disabled");
	return 0;
}

static int cmd_activetime(const struct shell *shell, size_t argc, char **argv)
{
	int err = 0;
	bool restart_ft;
	long value = strtol(argv[1], NULL, 10);

	ARG_UNUSED(argc);

	if (value < 1 || value > 100) {
		shell_error(shell, "ACTIVETIME must be between 1 and 100");
		return -EINVAL;
	}

	k_mutex_lock(&app_mutex, K_FOREVER);
	ft_rach_fill_percentage = (uint8_t)value;
	restart_ft = (current_mode == APP_MODE_FT);
	k_mutex_unlock(&app_mutex);

	if (restart_ft) {
		err = configure_ft();
	}

	if (err != 0) {
		shell_error(shell, "ACTIVETIME update failed: %d", err);
		return err;
	}

	shell_print(shell, "RACH fill percentage set to %u%%", ft_rach_fill_percentage);
	return 0;
}

static int cmd_stop(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	k_mutex_lock(&app_mutex, K_FOREVER);

	/* Release association if any */
	if (ft_child_associated && ft_child_long_rd_id != 0) {
		LOG_INF("STOP: releasing FT->PT association rd=%u", ft_child_long_rd_id);
		(void)dect_adapter_association_release(ft_child_long_rd_id);
	}
	if (pt_associated && pt_parent_long_rd_id != 0) {
		LOG_INF("STOP: releasing PT->FT association rd=%u", pt_parent_long_rd_id);
		(void)dect_adapter_association_release(pt_parent_long_rd_id);
	}

	current_mode = APP_MODE_IDLE;
	k_mutex_unlock(&app_mutex);

	/* init_mac stops scans, stops beaconing (functional_mode false/true), resets state */
	int err = init_mac(false);

	k_mutex_lock(&app_mutex, K_FOREVER);
	led_apply();
	k_mutex_unlock(&app_mutex);

	if (err != 0) {
		shell_error(shell, "STOP: rearm failed: %d", err);
		return err;
	}

	shell_print(shell, "Stopped — mode: IDLE");
	return 0;
}

static int cmd_limit(const struct shell *shell, size_t argc, char **argv)
{
	long min_val, max_val;

	if (argc < 3) {
		shell_print(shell, "RSSI thresholds: min=%d dBm  max=%d dBm", scan_threshold_min, scan_threshold_max);
		shell_print(shell, "  carrier is FREE if RSSI < min, BUSY if RSSI > max");
		shell_print(shell, "Usage: LIMIT <min_dBm> <max_dBm>  (e.g. LIMIT -90 -60)");
		return 0;
	}

	min_val = strtol(argv[1], NULL, 10);
	max_val = strtol(argv[2], NULL, 10);

	if (min_val < -127 || min_val > 0 || max_val < -127 || max_val > 0) {
		shell_error(shell, "Thresholds must be in range -127..0 dBm");
		return -EINVAL;
	}
	if (min_val >= max_val) {
		shell_error(shell, "min must be less than max");
		return -EINVAL;
	}

	scan_threshold_min = (int)min_val;
	scan_threshold_max = (int)max_val;
	shell_print(shell, "RSSI limits set: free if RSSI < %d dBm, busy if RSSI > %d dBm",
		    scan_threshold_min, scan_threshold_max);
	return 0;
}

static int cmd_help_dect(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	shell_print(shell, "=== DECT MAC Demo Commands ===");
	shell_print(shell, "");
	shell_print(shell, "  SCAN                    FT RSSI scan all Band 1 channels, prints ch/busy%%");
	shell_print(shell, "  FT [carrier]            Start FT beacon mode on carrier (default: last SCAN result)");
	shell_print(shell, "  PT_SCAN [channel]       Scan for FT beacons, populate discovery table (no association)");
	shell_print(shell, "  PT <channel>            Associate with FT on <channel> (must run PT_SCAN first)");
	shell_print(shell, "  PERIOD <ms>             Set FT cluster beacon period (50..32000 ms)");
	shell_print(shell, "  SEND <text>             Send ASCII text to associated peer");
	shell_print(shell, "  STATUS                  Show current mode, carrier, beacon table, association state");
	shell_print(shell, "  POWERSAVE <0|1>         Enable (1) or disable (0) power save mode (FT and PT)");
	shell_print(shell, "  ACTIVETIME <1-100>      Set FT RACH fill percentage (default 100)");
	shell_print(shell, "  STOP                    Release association, stop scans/beaconing, go idle");
	shell_print(shell, "  LIMIT [min max]         Show or set RSSI thresholds (dBm) for SCAN");
	shell_print(shell, "                          Free if RSSI < min, busy if RSSI > max");
	shell_print(shell, "");
	shell_print(shell, "  Typical FT workflow:  SCAN -> FT <carrier>");
	shell_print(shell, "  Typical PT workflow:  (fast) PT <channel> \t(slow mode) PT_SCAN -> PT <channel>");
	shell_print(shell, "  Stop everything:      STOP");
	return 0;
}

SHELL_CMD_ARG_REGISTER(SCAN,      NULL, "RSSI scan all Band 1 channels, print busy%",             cmd_scan,      1, 0);
SHELL_CMD_ARG_REGISTER(STOP,      NULL, "Stop all activity, return to idle",                       cmd_stop,      1, 0);
SHELL_CMD_ARG_REGISTER(SEND,      NULL, "SEND <ascii text>",                                       cmd_send,      2, 32);
SHELL_CMD_ARG_REGISTER(FT,        NULL, "Start FT beacon mode [carrier]",                          cmd_ft,        1, 1);
SHELL_CMD_ARG_REGISTER(PERIOD,    NULL, "PERIOD <ms>",                                             cmd_period,    2, 0);
SHELL_CMD_ARG_REGISTER(PT_SCAN,   NULL, "Scan for FT beacons [channel] — no association",         cmd_pt_scan,   1, 1);
SHELL_CMD_ARG_REGISTER(PT,        NULL, "Associate with FT on <channel> (run PT_SCAN first)",      cmd_pt,        2, 0);
SHELL_CMD_ARG_REGISTER(STATUS,    NULL, "Show mode, timing, channel",                              cmd_status,    1, 0);
SHELL_CMD_ARG_REGISTER(POWERSAVE,   NULL, "POWERSAVE 0|1",                                          cmd_powersave,   2, 0);
SHELL_CMD_ARG_REGISTER(ACTIVETIME, NULL, "ACTIVETIME <1-100> — FT RACH fill percentage",           cmd_activetime,  2, 0);
SHELL_CMD_ARG_REGISTER(LIMIT,      NULL, "LIMIT [min max] — RSSI thresholds for SCAN",             cmd_limit,       1, 2);
SHELL_CMD_ARG_REGISTER(HELP,       NULL, "Show command help",                                       cmd_help_dect,   1, 0);

/* Lowercase aliases */
SHELL_CMD_ARG_REGISTER(scan,       NULL, "rssi scan all band 1 channels, print busy%",             cmd_scan,        1, 0);
SHELL_CMD_ARG_REGISTER(stop,       NULL, "stop all activity, return to idle",                      cmd_stop,        1, 0);
SHELL_CMD_ARG_REGISTER(send,       NULL, "send <ascii text>",                                      cmd_send,        2, 32);
SHELL_CMD_ARG_REGISTER(ft,         NULL, "start ft beacon mode [carrier]",                         cmd_ft,          1, 1);
SHELL_CMD_ARG_REGISTER(period,     NULL, "period <ms>",                                            cmd_period,      2, 0);
SHELL_CMD_ARG_REGISTER(pt_scan,    NULL, "scan for ft beacons [channel] — no association",        cmd_pt_scan,     1, 1);
SHELL_CMD_ARG_REGISTER(pt,         NULL, "associate with ft on <channel> (run pt_scan first)",     cmd_pt,          2, 0);
SHELL_CMD_ARG_REGISTER(status,     NULL, "show mode, timing, channel",                             cmd_status,      1, 0);
SHELL_CMD_ARG_REGISTER(powersave,  NULL, "powersave 0|1",                                          cmd_powersave,   2, 0);
SHELL_CMD_ARG_REGISTER(activetime, NULL, "activetime <1-100> — ft rach fill percentage",           cmd_activetime,  2, 0);
SHELL_CMD_ARG_REGISTER(limit,      NULL, "limit [min max] — rssi thresholds for scan",            cmd_limit,       1, 2);
SHELL_CMD_ARG_REGISTER(help,       NULL, "show command help",                                      cmd_help_dect,   1, 0);

/* ============================================================================
 * MAIN
 * ========================================================================== */

int main(void)
{
	int err;
	ssize_t id_len;
	uint8_t id_buf[4] = {0};

	LOG_INF("### main START ###");

	err = dect_adapter_init();
	LOG_INF("dect_adapter_init: %d", err);
	if (err != 0) {
		LOG_ERR("dect_adapter_init failed: %d", err);
		return err;
	}

	err = dk_leds_init();
	if (err != 0) {
		LOG_ERR("dk_leds_init failed: %d", err);
	}
	id_len = hwinfo_get_device_id(id_buf, sizeof(id_buf));
	if (id_len < 0) {
		LOG_ERR("hwinfo_get_device_id failed: %d", (int)id_len);
		return (int)id_len;
	}

	for (size_t i = 0; i < sizeof(id_buf); i++) {
		device_long_rd_id = (device_long_rd_id << 8) | id_buf[i];
	}

	err = dect_adapter_callbacks_set(&app_op_callbacks, &app_ntf_callbacks);
	if (err != 0) {
		LOG_ERR("dect_adapter_callbacks_set failed: %d", err);
		return err;
	}

	LOG_DBG("Setting system mode to MAC...");
	prepare_wait(WAIT_SYSTEMMODE);
	err = dect_adapter_system_mode_set_mac();
	if (err != 0) {
		cancel_wait(WAIT_SYSTEMMODE);
		LOG_ERR("system_mode_set_mac failed: %d", err);
		return err;
	}

	err = wait_for_prepared_operation(WAIT_SYSTEMMODE, K_SECONDS(5));
	if (err != 0) {
		LOG_ERR("System mode set failed: %d", err);
		return err;
	}

	prepare_wait(WAIT_CONFIGURE);
	err = dect_adapter_control_configure(
		CONFIG_APP_TX_POWER, CONFIG_APP_MCS, CONFIG_APP_RX_EXPECTED_RSSI,
		device_long_rd_id, current_carrier, power_save_enabled);
	if (err != 0) {
		cancel_wait(WAIT_CONFIGURE);
		LOG_ERR("control_configure failed: %d", err);
		return err;
	}

	err = wait_for_prepared_operation(WAIT_CONFIGURE, K_SECONDS(5));
	if (err != 0) {
		LOG_ERR("Configure failed: %d", err);
		return err;
	}

	prepare_wait(WAIT_FUNCTIONAL);
	err = dect_adapter_functional_mode_set(true);
	if (err != 0) {
		cancel_wait(WAIT_FUNCTIONAL);
		LOG_ERR("Activate failed: %d", err);
		return err;
	}

	err = wait_for_prepared_operation(WAIT_FUNCTIONAL, K_SECONDS(5));
	if (err != 0) {
		LOG_ERR("Activation status failed: %d", err);
		return err;
	}

	printk("*** Functional mode activated - entering ready state ***\n");
	k_mutex_lock(&app_mutex, K_FOREVER);
	app_ready = true;
	reset_link_state();
	led_apply();
	k_mutex_unlock(&app_mutex);

	printk("=== DECT MAC Demo Ready ===\n");
	if (use_fixed_channel) {
		printk("Ready, long RD ID %u, network %u\n", device_long_rd_id, CONFIG_APP_NETWORK_ID);
		printk("FIXED CHANNEL carrier %u\n", current_carrier);
	} else {
		printk("Ready, long RD ID %u, network %u\n", device_long_rd_id, CONFIG_APP_NETWORK_ID);
	}
	printk("RSSI thresholds: free < %d dBm, busy > %d dBm (change with LIMIT <min> <max>)\n",
	       scan_threshold_min, scan_threshold_max);
	printk("Commands: SCAN, FT [carrier], PT_SCAN [channel], PT <channel>, SEND, PERIOD <ms>, STATUS, POWERSAVE <0|1>, LIMIT [min max], STOP, HELP\n");
	printk("Typical FT workflow:  SCAN -> FT <carrier>\n");
	printk("Typical PT workflow:  PT_SCAN -> PT <channel>\n");

	srand(k_cycle_get_32());
	while (true) {
		struct app_event evt;

		if (k_msgq_get(&app_evt_msgq, &evt, K_FOREVER) == 0) {
			process_app_event(&evt);
		}
	}
}
