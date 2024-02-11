/* SPDX-License-Identifier: GPL-2.0
 *
 * Utilities to parse DNS messages.
 */

#ifndef _DNS_H
#define _DNS_H

/*
struct dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answers;
	uint16_t authority;
	uint16_t additional;
} __attribute__((packed));
*/

void parse_dns(const uint8_t *pbuf, size_t plen);

#endif
