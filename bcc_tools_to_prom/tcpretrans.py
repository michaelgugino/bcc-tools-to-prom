# tcpretrans    Trace or count TCP retransmits and TLPs.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpretrans [-c] [-h] [-l]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Feb-2016   Brendan Gregg   Created this.
# 03-Nov-2017   Matthias Tafelmeier Extended this.
# 08-Jun-2021   Michael Gugino Adpated this.

from bcc import BPF
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep


from bcc_tools_to_prom.types import *

class TCPRetrans(BCCTool):
    # process event
    def print_ipv4_event(self, cpu, data, size):
        self.metricsd['tcpretrans4'] += 1
        event = self.b["ipv4_events"].event(data)
        print("tcpretrans: %-8s %-6d %-2d %-20s %1s> %-20s %s" % (
            strftime("%H:%M:%S"), event.pid, event.ip,
            "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.lport),
            type[event.type],
            "%s:%s" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
            tcpstate[event.state]))

    def print_ipv6_event(self, cpu, data, size):
        self.metricsd['tcpretrans6'] += 1
        event = self.b["ipv6_events"].event(data)
        print("tcpretrans: %-8s %-6d %-2d %-20s %1s> %-20s %s" % (
            strftime("%H:%M:%S"), event.pid, event.ip,
            "%s:%d" % (inet_ntop(AF_INET6, event.saddr), event.lport),
            type[event.type],
            "%s:%d" % (inet_ntop(AF_INET6, event.daddr), event.dport),
            tcpstate[event.state]))

    def setup(self):
        global bpf_text
        global bpf_text_tracepoint
        # initialize BPF
        if BPF.tracepoint_exists("tcp", "tcp_retransmit_skb"):
            bpf_text_tracepoint = bpf_text_tracepoint.replace("IPV4_CODE", struct_init_tracepoint['ipv4']['trace'])
            bpf_text_tracepoint = bpf_text_tracepoint.replace("IPV6_CODE", struct_init_tracepoint['ipv6']['trace'])
            bpf_text += bpf_text_tracepoint

        if not BPF.tracepoint_exists("tcp", "tcp_retransmit_skb"):
            bpf_text += bpf_text_kprobe
            bpf_text = bpf_text.replace("IPV4_INIT", struct_init['ipv4']['trace'])
            bpf_text = bpf_text.replace("IPV6_INIT", struct_init['ipv6']['trace'])
            bpf_text = bpf_text.replace("IPV4_CORE", "ipv4_events.perf_submit(ctx, &data4, sizeof(data4));")
            bpf_text = bpf_text.replace("IPV6_CORE", "ipv6_events.perf_submit(ctx, &data6, sizeof(data6));")

            bpf_text += bpf_text_kprobe_retransmit

        b = BPF(text=bpf_text)
        if not BPF.tracepoint_exists("tcp", "tcp_retransmit_skb"):
            b.attach_kprobe(event="tcp_retransmit_skb", fn_name="trace_retransmit")

        self.b = b

    def run(self):
        # header
        # print("tcpretrans: %-8s %-6s %-2s %-20s %1s> %-20s %-4s" % ("TIME", "PID", "IP",
        #     "LADDR:LPORT", "T", "RADDR:RPORT", "STATE"))
        self.metricsd['tcpretrans4'] = 0
        self.metricsd['tcpretrans6'] = 0
        self.b["ipv4_events"].open_perf_buffer(self.print_ipv4_event)
        self.b["ipv6_events"].open_perf_buffer(self.print_ipv6_event)
        while 1:
            try:
                self.b.perf_buffer_poll()
            except:
                return 0


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#define RETRANSMIT  1
#define TLP         2
// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u32 pid;
    u64 ip;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u64 state;
    u64 type;
};
BPF_PERF_OUTPUT(ipv4_events);
struct ipv6_data_t {
    u32 pid;
    u64 ip;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
    u64 state;
    u64 type;
};
BPF_PERF_OUTPUT(ipv6_events);
// separate flow keys per address family
struct ipv4_flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv4_count, struct ipv4_flow_key_t);
struct ipv6_flow_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv6_count, struct ipv6_flow_key_t);
"""

bpf_text_kprobe = """
static int trace_event(struct pt_regs *ctx, struct sock *skp, int type)
{
    if (skp == NULL)
        return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    // pull in details
    u16 family = skp->__sk_common.skc_family;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    char state = skp->__sk_common.skc_state;
    if (family == AF_INET) {
        IPV4_INIT
        IPV4_CORE
    } else if (family == AF_INET6) {
        IPV6_INIT
        IPV6_CORE
    }
    // else drop
    return 0;
}
"""

bpf_text_kprobe_retransmit = """
int trace_retransmit(struct pt_regs *ctx, struct sock *sk)
{
    trace_event(ctx, sk, RETRANSMIT);
    return 0;
}
"""

bpf_text_kprobe_tlp = """
int trace_tlp(struct pt_regs *ctx, struct sock *sk)
{
    trace_event(ctx, sk, TLP);
    return 0;
}
"""

bpf_text_tracepoint = """
TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    const struct sock *skp = (const struct sock *)args->skaddr;
    u16 lport = args->sport;
    u16 dport = args->dport;
    char state = skp->__sk_common.skc_state;
    u16 family = skp->__sk_common.skc_family;
    if (family == AF_INET) {
        IPV4_CODE
    } else if (family == AF_INET6) {
        IPV6_CODE
    }
    return 0;
}
"""

struct_init = { 'ipv4':
        { 'count' :
            """
               struct ipv4_flow_key_t flow_key = {};
               flow_key.saddr = skp->__sk_common.skc_rcv_saddr;
               flow_key.daddr = skp->__sk_common.skc_daddr;
               // lport is host order
               flow_key.lport = lport;
               flow_key.dport = ntohs(dport);""",
               'trace' :
               """
               struct ipv4_data_t data4 = {};
               data4.pid = pid;
               data4.ip = 4;
               data4.type = type;
               data4.saddr = skp->__sk_common.skc_rcv_saddr;
               data4.daddr = skp->__sk_common.skc_daddr;
               // lport is host order
               data4.lport = lport;
               data4.dport = ntohs(dport);
               data4.state = state; """
               },
        'ipv6':
        { 'count' :
            """
                    struct ipv6_flow_key_t flow_key = {};
                    bpf_probe_read_kernel(&flow_key.saddr, sizeof(flow_key.saddr),
                        skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
                    bpf_probe_read_kernel(&flow_key.daddr, sizeof(flow_key.daddr),
                        skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
                    // lport is host order
                    flow_key.lport = lport;
                    flow_key.dport = ntohs(dport);""",
          'trace' : """
                    struct ipv6_data_t data6 = {};
                    data6.pid = pid;
                    data6.ip = 6;
                    data6.type = type;
                    bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
                        skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
                    bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
                        skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
                    // lport is host order
                    data6.lport = lport;
                    data6.dport = ntohs(dport);
                    data6.state = state;"""
                }
        }

struct_init_tracepoint = { 'ipv4':
        { 'count' : """
               struct ipv4_flow_key_t flow_key = {};
               __builtin_memcpy(&flow_key.saddr, args->saddr, sizeof(flow_key.saddr));
               __builtin_memcpy(&flow_key.daddr, args->daddr, sizeof(flow_key.daddr));
               flow_key.lport = lport;
               flow_key.dport = dport;
               ipv4_count.increment(flow_key);
               """,
          'trace' : """
               struct ipv4_data_t data4 = {};
               data4.pid = pid;
               data4.lport = lport;
               data4.dport = dport;
               data4.type = RETRANSMIT;
               data4.ip = 4;
               data4.state = state;
               __builtin_memcpy(&data4.saddr, args->saddr, sizeof(data4.saddr));
               __builtin_memcpy(&data4.daddr, args->daddr, sizeof(data4.daddr));
               ipv4_events.perf_submit(args, &data4, sizeof(data4));
               """
               },
        'ipv6':
        { 'count' : """
               struct ipv6_flow_key_t flow_key = {};
               __builtin_memcpy(&flow_key.saddr, args->saddr_v6, sizeof(flow_key.saddr));
               __builtin_memcpy(&flow_key.daddr, args->daddr_v6, sizeof(flow_key.daddr));
               flow_key.lport = lport;
               flow_key.dport = dport;
               ipv6_count.increment(flow_key);
               """,
          'trace' : """
               struct ipv6_data_t data6 = {};
               data6.pid = pid;
               data6.lport = lport;
               data6.dport = dport;
               data6.type = RETRANSMIT;
               data6.ip = 6;
               data6.state = state;
               __builtin_memcpy(&data6.saddr, args->saddr_v6, sizeof(data6.saddr));
               __builtin_memcpy(&data6.daddr, args->daddr_v6, sizeof(data6.daddr));
               ipv6_events.perf_submit(args, &data6, sizeof(data6));
               """
               }
        }

count_core_base = """
        COUNT_STRUCT.increment(flow_key);
"""

# from bpf_text:
type = {}
type[1] = 'R'
type[2] = 'L'

# from include/net/tcp_states.h:
tcpstate = {}
tcpstate[1] = 'ESTABLISHED'
tcpstate[2] = 'SYN_SENT'
tcpstate[3] = 'SYN_RECV'
tcpstate[4] = 'FIN_WAIT1'
tcpstate[5] = 'FIN_WAIT2'
tcpstate[6] = 'TIME_WAIT'
tcpstate[7] = 'CLOSE'
tcpstate[8] = 'CLOSE_WAIT'
tcpstate[9] = 'LAST_ACK'
tcpstate[10] = 'LISTEN'
tcpstate[11] = 'CLOSING'
tcpstate[12] = 'NEW_SYN_RECV'
