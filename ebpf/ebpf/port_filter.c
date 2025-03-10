#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "helper.h"

// 로그 메시지를 위한 포맷 문자열
#define MAX_LOG_SIZE 256

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);    // 포트 번호
    __type(value, __u8);   // 1이면 차단
} blocked_ports SEC(".maps");

// 로그를 위한 링 버퍼 맵 추가
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB */
} rb SEC(".maps");

// 로그 이벤트 구조체
struct log_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u64 timestamp;
};

SEC("xdp")
int xdp_filter_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 이더넷 헤더 확인
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // IP 패킷이 아니면 통과
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // IP 헤더 확인
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    __u8 protocol = ip->protocol;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    
    // TCP 패킷 확인
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } 
    // UDP 패킷 확인
    else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    } 
    // 그 외는 통과
    else {
        return XDP_PASS;
    }
    
    // 목적지 포트가 차단 목록에 있는지 확인
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ports, &dst_port);
    if (blocked && *blocked == 1) {
        // 로그 기록
        struct log_event *event;
        event = bpf_ringbuf_reserve(&rb, sizeof(struct log_event), 0);
        if (event) {
            event->src_ip = ip->saddr;
            event->dst_ip = ip->daddr;
            event->src_port = src_port;
            event->dst_port = dst_port;
            event->protocol = protocol;
            event->timestamp = bpf_ktime_get_ns();
            
            bpf_ringbuf_submit(event, 0);
        }
        // 차단 목록에 있으면 패킷 드롭
        return XDP_DROP;
    }
    
    // 차단 목록에 없으면 통과
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";