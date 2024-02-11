/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <string.h>

#include "dns.h"

struct dns_header {
	uint16_t id;
	union {
		struct {
			uint8_t qr:1;
			uint8_t opcode:4;
			uint8_t aa:1;
			uint8_t tc:1;
			uint8_t rd:1;
			uint8_t ra:1;
			uint8_t z:3;
			uint8_t rcode:4;
		} __attribute__((packed));
		uint16_t flags;
	};
	uint16_t questions;
	uint16_t answers;
	uint16_t authority;
	uint16_t additional;
} __attribute__((packed));

struct dns_query {
	uint16_t qtype;
	uint16_t qclass;
} __attribute__((packed));

struct dns_response {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
	uint8_t rdata[];
} __attribute__((packed));

#define be16_to_cpu(x) ntohs((x))
#define cpu_to_be16(x) htons((x))

#define TYPE_A			0x0001
#define TYPE_PTR		0x000C
#define TYPE_TXT		0x0010
#define TYPE_AAAA		0x001c
#define TYPE_SRV		0x0021
#define TYPE_ANY		0x00ff

#define CLASS_IN		0x0001

static const char *
type_str(uint16_t type)
{
	switch (type) {
	case TYPE_A:
		return "A";
	case TYPE_PTR:
		return "PTR";
	case TYPE_TXT:
		return "TXT";
	case TYPE_AAAA:
		return "AAAA";
	case TYPE_SRV:
		return "SRV";
	case TYPE_ANY:
		return "ANY";
	default:
		return "UNKNOWN";
	}
}

static const char *
class_str(uint16_t class)
{
	switch (class) {
	case CLASS_IN:
		return "IN";
	default:
		return "UNKNOWN";
	}
}

static const uint8_t *
parse_label(const uint8_t *pkt, size_t plen, const uint8_t *bbuf, size_t blen, size_t *consumed)
{
	uint8_t llen;
	int lc = 0;
	static uint8_t lstr[255];
	uint8_t *tmp = lstr;
	size_t blen_orig = blen;
	int pointer = 0;

	while (blen > 0) {
		llen = *bbuf++;
		blen--;

		//printf("Looking at llen 0x%02" PRIx8 "\n", llen & 0xff);
		if ((llen & 0xc0) == 0xc0) {
			uint16_t offset = ((llen & 0x3f) << 8) + (*bbuf++);
			blen--;
			// pointer
			if (pointer) {
				printf("Multiple pointers!?\n");
				return NULL;
			}
			printf("Pointer %" PRIu16 " (0x%04" PRIx16 ")\n", offset, offset);
			pointer = 1;
			bbuf = pkt + offset;
			blen = plen - offset;
			continue;
		}

		if (llen > blen) {
			printf("Label length %" PRIu8 " exceeds packet len\n", llen);
			return NULL;
		} else if (llen > 63) {
			printf("Invalid label length %" PRIu8 "\n", llen);
			return NULL;
		} else if (llen == 0) {
			*tmp = '\0';
			*consumed = (blen_orig - blen);
			return lstr;
		}

		memcpy(tmp, bbuf, llen);
		tmp += llen;
		*tmp++ = '.';

		bbuf += llen;
		blen -= llen;
		lc++;
	}
}

static void
parse_response(const uint8_t *pkt, size_t plen, const uint8_t *body, size_t blen)
{
	const char *qname;
	struct dns_response *response;
	size_t consumed;
	uint16_t type, class;
	uint32_t ttl;
	uint16_t rdlen;

	qname = parse_label(pkt, plen, body, blen, &consumed);
	if (!qname)
		return;

	body += consumed;
	blen -= consumed;

	if (blen < sizeof(*response)) {
		printf("Invalid response len\n");
		return;
	}

	response = (struct dns_response *)body;

	type = be16_to_cpu(response->type);
	class = be16_to_cpu(response->class);
	ttl = ntohl(response->ttl);
	rdlen = be16_to_cpu(response->rdlength);

	printf("Response:\n");
	printf("  Name   : %s\n", qname);
	printf("  Type   : 0x%04" PRIx16 " (%s)\n", type, type_str(type));
	printf("  Class  : 0x%04" PRIx16 " (%s)\n", class, class_str(class));
	printf("  TTL    : %" PRIu32 "\n", ttl);
	printf("  RDLen  : %" PRIu16 "\n", rdlen);

	body += sizeof(*response);
	blen -= sizeof(*response);

	if ((class & 0x7fff) != CLASS_IN)
		return;

	if (type == TYPE_A) {
		struct in_addr addr;
		char a[INET_ADDRSTRLEN];

		if (rdlen != sizeof(addr)) {
			printf("Invalid A len (%" PRIu16 ")\n", rdlen);
			return;
		}

		memcpy(&addr.s_addr, body, sizeof(addr.s_addr));
		inet_ntop(AF_INET, &addr, a, sizeof(a));
		printf("  A      : %s\n", a);

	} else if (type == TYPE_AAAA) {
		struct in6_addr addr;
		char aaaa[INET6_ADDRSTRLEN];

		if (rdlen != 16) {
			printf("Invalid AAAA len (%" PRIu16 ")\n", rdlen);
			return;
		}

		memcpy(&addr.s6_addr, body, sizeof(addr.s6_addr));
		inet_ntop(AF_INET6, &addr, aaaa, sizeof(aaaa));
		printf("  AAAA   : %s\n", aaaa);

	} else if (type == TYPE_PTR) {
		const char *ptrdname;

		//printf("Doing PTR: *body is %u (0x%02X), blen %zu\n", *body, *body, blen);
		ptrdname = parse_label(pkt, plen, body, blen, &consumed);
		if (!ptrdname)
			return;

		printf("  Dest   : %s\n", ptrdname);
	}
}

static void
parse_query(const uint8_t *pkt, size_t plen, const uint8_t *body, size_t blen)
{
	const char *qname;
	struct dns_query *query;
	size_t consumed;
	uint16_t qtype, qclass;

	qname = parse_label(pkt, plen, body, blen, &consumed);
	if (!qname)
		return;
	printf("QNAME: %s\n", qname);

	body += consumed;
	blen -= consumed;

	if (blen < sizeof(*query)) {
		printf("Invalid query len\n");
		return;
	}

	query = (struct dns_query *)body;

	qtype = be16_to_cpu(query->qtype);
	qclass = be16_to_cpu(query->qclass);
	printf("Query: \n");
	printf("  Name   : %s\n", qname);
	printf("  QType  : 0x%04" PRIx16 " (%s)\n", qtype, type_str(qtype));
	printf("  QClass : 0x%04" PRIx16 " (%s)\n", qclass, class_str(qclass));

	body += sizeof(*query);
	blen -= sizeof(*query);
}

#define DNS_FLAG_QR	0x8000
#define DNS_OPCODE(x)	(((x) >> 11) & 0x000f)
#define DNS_FLAG_AA	0x0400
#define DNS_FLAG_TC	0x0200
#define DNS_FLAG_RD	0x0100
#define DNS_FLAG_RA	0x0080
#define DNS_Z(x)	(((x) >> 4) & 0x0007)
#define DNS_RCODE(x)	(((x) >> 0) & 0x000f)
void
parse_dns(const uint8_t *pbuf, size_t plen)
{
	struct dns_header *header = (struct dns_header *)pbuf;
	const uint8_t *body;
	size_t blen;
	uint16_t id, flags, questions, answers, authority, additional;

	if (plen < sizeof(*header)) {
		printf("Invalid packet size (too short): %zu < %zu\n", plen, sizeof(*header));
		return;
	}

	id = be16_to_cpu(header->id);
	flags = be16_to_cpu(header->flags);
	questions = be16_to_cpu(header->questions);
	answers = be16_to_cpu(header->answers);
	authority = be16_to_cpu(header->authority);
	additional = be16_to_cpu(header->additional);

	printf("\n\n\n");
	printf("Packet header (packet size %zu, hdr %zu):\n", plen, sizeof(*header));
	printf("  ID         : %" PRIu16 "\n", id);
	printf("  Flags      : 0x%04" PRIx16 "\n", flags);
	/*
	printf("    QR       : %c\n", flags & DNS_FLAG_QR ? 'R' : 'Q');
	printf("    OPCode   : 0x%" PRIx16 "\n", DNS_OPCODE(flags));
	printf("    AA       : %s\n", flags & DNS_FLAG_AA ? "true" : "false");
	printf("    TC       : %s\n", flags & DNS_FLAG_TC ? "true" : "false");
	printf("    RD       : %s\n", flags & DNS_FLAG_RD ? "true" : "false");
	printf("    RA       : %s\n", flags & DNS_FLAG_RA ? "true" : "false");
	printf("    Z        : 0x%" PRIx16 "\n", DNS_Z(flags));
	printf("    RCode    : 0x%" PRIx16 "\n", DNS_RCODE(flags));
	*/
	printf("  Questions  : %" PRIu16 "\n", questions);
	printf("  Answers    : %" PRIu16 "\n", answers);
	printf("  Authority  : %" PRIu16 "\n", authority);
	printf("  Additional : %" PRIu16 "\n", additional);

	body = pbuf + sizeof(*header);
	blen = plen - sizeof(*header);

	if (flags & DNS_FLAG_QR)
		parse_response(pbuf, plen, body, blen);
	else
		parse_query(pbuf, plen, body, blen);

	//uint8_t *body = pbuf + sizeof(*header);
	printf("\n");
	return;
	printf("Packet body (len: %zu):\n", plen - sizeof(*header));
	for (int i = 0; i < blen; i++) {
		printf("0x%02X(%c) ", body[i] & 0xff, isalnum(body[i]) ? body[i] : '?');
		if (i % 8 == 7)
			printf("\n");
	}
	printf("\n");
}
