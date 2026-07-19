#pragma once
#include "common.h"

typedef enum { NAT_UNKNOWN=0, NAT_CONE, NAT_SYMMETRIC } nat_type_t;

/* --- server list --------------------------------------------------------
 *
 * The servers below are contacted in order until one answers, so a dead or
 * blocked provider costs a timeout rather than the whole srflx candidate.
 * The built-in default deliberately spans several operators: probing two of
 * them is what distinguishes cone from symmetric, and a single-operator list
 * makes that test (and the srflx candidate itself) fail as one unit if that
 * operator is unreachable.
 *
 * Override with the STUN_SERVERS environment variable: a comma- or
 * space-separated list of `host[:port]` entries, port defaulting to 3478.
 * IPv6 literals must be bracketed to carry a port (`[2001:db8::1]:3478`).
 * An unset, empty, or wholly unparseable value leaves the defaults in place.
 *
 * Parsed once on first use and then read-only. All STUN calls in telegloomy
 * are made from the main thread, so this needs no lock; a caller that STUNs
 * from several threads must force the parse first (any accessor will do).
 */
#define STUN_MAX_SERVERS 8
int         stun_server_count(void);
const char *stun_server_host(int i);   /* NULL if i is out of range */
const char *stun_server_port(int i);

/* Two STUN probes to different servers from the same socket; compares the
 * mapped endpoints. Same mapping => endpoint-independent (cone, punchable);
 * different => symmetric. Uses the first two configured servers that answer,
 * so one being down degrades to NAT_UNKNOWN rather than a wrong verdict.
 * *mapped gets a discovered srflx (if any). */
nat_type_t nat_detect(int fd, ep_t *mapped);

/* Server-reflexive lookup over the configured server list, from an existing
 * (bound) UDP socket -- required so the mapping matches the socket used for
 * hole punching and data. Returns 0 on success. */
int stun_srflx(int fd, ep_t *out);    /* IPv4 (v4-mapped on a dual-stack sock) */
int stun_srflx6(int fd, ep_t *out);   /* real IPv6; -1 on a v4-only socket    */

/* Single-server forms, for probing one specific server (see tests). */
int stun_query_on(int fd, const char *host, const char *port, ep_t *out);
int stun_query6_on(int fd, const char *host, const char *port, ep_t *out);
