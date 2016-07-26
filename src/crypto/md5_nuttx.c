/*
 * MD5 hash implementation for NuttX
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
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
#include "md5.h"
#include "md5_i.h"
#include "crypto.h"


/**
 * md5_vector - MD5 hash for data vector
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash
 * Returns: 0 on success, -1 of failure
 */
int md5_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	struct MD5Context ctx;
	size_t i;

	MD5Init(&ctx);
	for (i = 0; i < num_elem; i++)
		MD5Update(&ctx, addr[i], len[i]);
	MD5Final(mac, &ctx);
	return 0;
}
