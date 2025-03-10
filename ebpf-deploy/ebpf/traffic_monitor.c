#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "helper.h"

// 포트 필터 맵: 차단 또는 모니터링할 포트 목록
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);    // 포트 번호
    __type(value, __u8);   // 1: 차단, 2: 모니터링
} port_map SEC(".maps");

// 트래픽 통계 맵: 포트별로 패킷 및 바이트 수 집계
struct traffic_stats {
    __u64 packets;    // 패킷 수
    __u64 bytes;      // 총 바이트 수
    __u64 last_seen;  // 마지막 패킷 타임스탬프
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);             // 포트 번호
    __type(value, struct traffic_stats);  // 트래픽 통계
} traffic_map SEC(".maps");

// 로그를 위한 링 버퍼 맵
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
    __u32 size;      // 패킷 크기
    __u8 action;     // 0: 통과, 1: 차단, 2: 모니터링
};

SEC("xdp")
int xdp_traffic_monitor(struct xdp_md *ctx) {
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
    __u32 size = data_end - data;
    
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
    
    // 포트맵에서 목적지 포트 확인
    __u8 *action = bpf_map_lookup_elem(&port_map, &dst_port);
    
    // 포트가 맵에 있으면 (차단 또는 모니터링)
    if (action) {
        // 트래픽 통계 업데이트
        struct traffic_stats stats = {0};
        struct traffic_stats *existing_stats = bpf_map_lookup_elem(&traffic_map, &dst_port);
        
        if (existing_stats) {
            stats = *existing_stats;
        }
        
        stats.packets++;
        stats.bytes += size;
        stats.last_seen = bpf_ktime_get_ns();
        
        bpf_map_update_elem(&traffic_map, &dst_port, &stats, BPF_ANY);
        
        // 로그 이벤트 생성
        struct log_event *event;
        event = bpf_ringbuf_reserve(&rb, sizeof(struct log_event), 0);
        if (event) {
            event->src_ip = ip->saddr;
            event->dst_ip = ip->daddr;
            event->src_port = src_port;
            event->dst_port = dst_port;
            event->protocol = protocol;
            event->timestamp = stats.last_seen;
            event->size = size;
            event->action = *action;
            
            bpf_ringbuf_submit(event, 0);
        }
        
        // 차단 모드인 경우 패킷 드롭
        if (*action == 1) {
            return XDP_DROP;
        }
    }
    
    // 통과
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";