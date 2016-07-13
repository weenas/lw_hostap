/*
 * Event loop based on select() loop
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"

#include "common.h"
#include "trace.h"
#include "list.h"
#include "eloop.h"


struct eloop_timeout {
	struct dl_list list;
	struct os_time time;
	void *eloop_data;
	void *user_data;
	int online;
	eloop_timeout_handler handler;
	WPA_TRACE_REF(eloop);
	WPA_TRACE_REF(user);
	WPA_TRACE_INFO
};



struct eloop_data {

	struct dl_list timeout;

	int pending_terminate;

	int terminate;
	struct eloop_timeout   timeout_cnt[MAX_TIMER_COUNT];
};

static struct eloop_data eloop;


#ifdef WPA_TRACE

static void eloop_sigsegv_handler(int sig)
{
	wpa_trace_show("eloop SIGSEGV");
	abort();
}

static void eloop_trace_sock_add_ref(struct eloop_sock_table *table)
{
	int i;
	if (table == NULL || table->table == NULL)
		return;
	for (i = 0; i < table->count; i++) {
		wpa_trace_add_ref(&table->table[i], eloop,
				  table->table[i].eloop_data);
		wpa_trace_add_ref(&table->table[i], user,
				  table->table[i].user_data);
	}
}


static void eloop_trace_sock_remove_ref(struct eloop_sock_table *table)
{
	int i;
	if (table == NULL || table->table == NULL)
		return;
	for (i = 0; i < table->count; i++) {
		wpa_trace_remove_ref(&table->table[i], eloop,
				     table->table[i].eloop_data);
		wpa_trace_remove_ref(&table->table[i], user,
				     table->table[i].user_data);
	}
}

#else /* WPA_TRACE */

#define eloop_trace_sock_add_ref(table) do { } while (0)
#define eloop_trace_sock_remove_ref(table) do { } while (0)

#endif /* WPA_TRACE */


int eloop_init(void)
{
	os_memset(&eloop, 0, sizeof(eloop));
	dl_list_init(&eloop.timeout);
#ifdef WPA_TRACE
	signal(SIGSEGV, eloop_sigsegv_handler);
#endif /* WPA_TRACE */
	return 0;
}

struct eloop_timeout *eloop_get_free_timer(void)
{
	int i = 0;

	for (i = 0; i < MAX_TIMER_COUNT; i++) {
		if (eloop.timeout_cnt[i].online != 1) {
			eloop.timeout_cnt[i].online = 1;
			return &eloop.timeout_cnt[i];
		}
	}
	return NULL;
}
inline void  eloop_put_free_timer(struct eloop_timeout *timeout)
{

	timeout->online = 0;

}

int eloop_register_timeout(unsigned int secs, unsigned int usecs,
			   eloop_timeout_handler handler,
			   void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *tmp;

	timeout = eloop_get_free_timer();
	if (timeout == NULL)
		return -1;
	if (os_get_time(&timeout->time) < 0) {
		eloop_put_free_timer(timeout);
		return -1;
	}
	timeout->time.sec += secs;
	timeout->time.usec += usecs;
	while (timeout->time.usec >= 1000000) {
		timeout->time.sec++;
		timeout->time.usec -= 1000000;
	}
	timeout->eloop_data = eloop_data;
	timeout->user_data = user_data;
	timeout->handler = handler;
	wpa_trace_add_ref(timeout, eloop, eloop_data);
	wpa_trace_add_ref(timeout, user, user_data);
	wpa_trace_record(timeout);

	/* Maintain timeouts in order of increasing time */
	dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
		if (os_time_before(&timeout->time, &tmp->time)) {
			dl_list_add(tmp->list.prev, &timeout->list);
			return 0;
		}
	}
	dl_list_add_tail(&eloop.timeout, &timeout->list);

	return 0;
}


static void eloop_remove_timeout(struct eloop_timeout *timeout)
{
	dl_list_del(&timeout->list);
	wpa_trace_remove_ref(timeout, eloop, timeout->eloop_data);
	wpa_trace_remove_ref(timeout, user, timeout->user_data);
	eloop_put_free_timer(timeout);
}


int eloop_cancel_timeout(eloop_timeout_handler handler,
			 void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *prev;
	int removed = 0;

	dl_list_for_each_safe(timeout, prev, &eloop.timeout,
			      struct eloop_timeout, list) {
		if (timeout->handler == handler &&
		    (timeout->eloop_data == eloop_data ||
		     eloop_data == ELOOP_ALL_CTX) &&
		    (timeout->user_data == user_data ||
		     user_data == ELOOP_ALL_CTX)) {
			eloop_remove_timeout(timeout);
			removed++;
		}
	}

	return removed;
}


int eloop_is_timeout_registered(eloop_timeout_handler handler,
				void *eloop_data, void *user_data)
{
	struct eloop_timeout *tmp;

	dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
		if (tmp->handler == handler &&
		    tmp->eloop_data == eloop_data &&
		    tmp->user_data == user_data)
			return 1;
	}

	return 0;
}


void eloop_run(void)
{
	struct timeval _tv;
	struct os_time tv, now;

	while (!eloop.terminate) {
		struct eloop_timeout *timeout;
		timeout = dl_list_first(&eloop.timeout, struct eloop_timeout,
					list);
		if (timeout) {
			os_get_time(&now);
			if (os_time_before(&now, &timeout->time))
				os_time_sub(&timeout->time, &now, &tv);
			else
				tv.sec = tv.usec = 0;
			_tv.tv_sec = tv.sec;
			_tv.tv_usec = tv.usec;
		}

		/* check if some registered timeouts have occurred */
		timeout = dl_list_first(&eloop.timeout, struct eloop_timeout,
					list);
		if (timeout) {
			os_get_time(&now);
			if (!os_time_before(&now, &timeout->time)) {
				void *eloop_data = timeout->eloop_data;
				void *user_data = timeout->user_data;
				eloop_timeout_handler handler =
					timeout->handler;
				eloop_remove_timeout(timeout);
				handler(eloop_data, user_data);
			}
		}
	}
}


void eloop_terminate(void)
{
	eloop.terminate = 1;
}


void eloop_destroy(void)
{
	struct eloop_timeout *timeout, *prev;
	struct os_time now;

	os_get_time(&now);
	dl_list_for_each_safe(timeout, prev, &eloop.timeout,
			      struct eloop_timeout, list) {
		int sec, usec;
		sec = timeout->time.sec - now.sec;
		usec = timeout->time.usec - now.usec;
		if (timeout->time.usec < now.usec) {
			sec--;
			usec += 1000000;
		}
		wpa_printf(MSG_INFO, "ELOOP: remaining timeout: %d.%06d "
			   "eloop_data=%p user_data=%p handler=%p",
			   sec, usec, timeout->eloop_data, timeout->user_data,
			   timeout->handler);
		wpa_trace_dump_funcname("eloop unregistered timeout handler",
					timeout->handler);
		wpa_trace_dump("eloop timeout", timeout);
		eloop_remove_timeout(timeout);
	}

}


int eloop_terminated(void)
{
	return eloop.terminate;
}

