package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"bytes"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang PortFilter ./ebpf/port_filter.c -- -I./ebpf/headers

// LogEvent는 eBPF에서 전달된 로그 이벤트를 저장하는 구조체입니다.
type LogEvent struct {
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Timestamp uint64
}

// 로그 이벤트를 사람이 읽기 쉬운 형태로 변환합니다.
func (e *LogEvent) String() string {
	srcIP := net.IPv4(
		byte(e.SrcIP),
		byte(e.SrcIP>>8),
		byte(e.SrcIP>>16),
		byte(e.SrcIP>>24),
	)
	dstIP := net.IPv4(
		byte(e.DstIP),
		byte(e.DstIP>>8),
		byte(e.DstIP>>16),
		byte(e.DstIP>>24),
	)
	
	protoName := "Unknown"
	switch e.Protocol {
	case 6:
		protoName = "TCP"
	case 17:
		protoName = "UDP"
	}
	
	timestamp := time.Unix(0, int64(e.Timestamp))
	
	return fmt.Sprintf("[%s] %s:%d -> %s:%d (%s)",
		timestamp.Format(time.RFC3339),
		srcIP.String(), e.SrcPort,
		dstIP.String(), e.DstPort,
		protoName)
}

// 차단할 포트를 관리하는 구조체
type PortBlocker struct {
	mu          sync.RWMutex
	blockedMap  *ebpf.Map
	blockedList map[uint16]bool
	logChan     chan LogEvent
}

func NewPortBlocker(blockedMap *ebpf.Map, logChan chan LogEvent) *PortBlocker {
	return &PortBlocker{
		blockedMap:  blockedMap,
		blockedList: make(map[uint16]bool),
		logChan:     logChan,
	}
}

func (pb *PortBlocker) BlockPort(port uint16) error {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// 이미 차단된 포트인지 확인
	if pb.blockedList[port] {
		return fmt.Errorf("port %d is already blocked", port)
	}

	// eBPF 맵에 포트 추가
	key := port
	value := uint8(1)
	if err := pb.blockedMap.Put(key, value); err != nil {
		return fmt.Errorf("failed to update eBPF map: %v", err)
	}

	// 차단 목록에 추가
	pb.blockedList[port] = true
	log.Printf("Port %d has been blocked", port)
	return nil
}

func (pb *PortBlocker) UnblockPort(port uint16) error {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// 차단된 포트인지 확인
	if !pb.blockedList[port] {
		return fmt.Errorf("port %d is not blocked", port)
	}

	// eBPF 맵에서 포트 제거
	key := port
	if err := pb.blockedMap.Delete(key); err != nil {
		return fmt.Errorf("failed to delete from eBPF map: %v", err)
	}

	// 차단 목록에서 제거
	delete(pb.blockedList, port)
	log.Printf("Port %d has been unblocked", port)
	return nil
}

func (pb *PortBlocker) GetBlockedPorts() []uint16 {
	pb.mu.RLock()
	defer pb.mu.RUnlock()

	ports := make([]uint16, 0, len(pb.blockedList))
	for port := range pb.blockedList {
		ports = append(ports, port)
	}
	return ports
}

// eBPF trace_pipe에서 로그를 읽는 함수
func readTracePipe() {
	f, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		log.Printf("Warning: Could not open trace_pipe: %v", err)
		return
	}
	defer f.Close()

	buf := make([]byte, 1024)
	for {
		n, err := f.Read(buf)
		if err != nil {
			log.Printf("Error reading trace_pipe: %v", err)
			return
		}
		if n > 0 {
			log.Printf("eBPF trace: %s", string(buf[:n]))
		}
	}
}

// RingBuffer에서 로그 이벤트를 읽는 함수
func readRingBuffer(rb *ringbuf.Reader, logChan chan LogEvent) {
	var event LogEvent
	for {
		record, err := rb.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			log.Printf("Error reading from ring buffer: %v", err)
			continue
		}

		// 레코드를 LogEvent 구조체로 변환
		if len(record.RawSample) < binary.Size(event) {
			log.Printf("Record too small: %d", len(record.RawSample))
			continue
		}

		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			log.Printf("Failed to parse event: %v", err)
			continue
		}

		// 로그 채널로 이벤트 전송
		logChan <- event
		
		// 또한 로그도 출력
		log.Printf("Blocked packet: %s", event.String())
	}
}

func main() {
	// eBPF의 메모리 한도 설정
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memory limit: %v", err)
	}

	// 사용 가능한 네트워크 인터페이스 목록 출력
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Failed to get interfaces: %v", err)
	}

	log.Println("Available interfaces:")
	for _, iface := range ifaces {
		log.Printf("- %s (index: %d)", iface.Name, iface.Index)
	}

	// eBPF 프로그램 로드
	objs := PortFilterObjects{}
	if err := LoadPortFilterObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// 로그 이벤트 채널 생성
	logChan := make(chan LogEvent, 100)

	// XDP 프로그램을 네트워크 인터페이스에 연결
	ifaceName := "eth0" // 사용자 환경에 맞게 수정해야 함
	log.Printf("Attaching XDP program to interface: %s", ifaceName)

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	}

	// generic 모드를 사용하여 XDP 프로그램 연결 시도
	ifaceLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFilterPort,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // generic 모드 사용
	})
	if err != nil {
		log.Printf("Failed to attach XDP in generic mode: %v", err)
		log.Printf("Falling back to native mode...")
		
		// generic 모드가 실패하면 native 모드로 시도
		ifaceLink, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpFilterPort,
			Interface: iface.Index,
		})
		if err != nil {
			log.Fatalf("Failed to attach XDP program: %v", err)
		}
	}
	defer ifaceLink.Close()
	log.Printf("XDP program attached successfully to %s", ifaceName)

	// RingBuffer 설정
	rb, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Fatalf("Failed to create ring buffer reader: %v", err)
	}
	defer rb.Close()

	// RingBuffer 읽기 goroutine 시작
	go readRingBuffer(rb, logChan)
	
	// trace_pipe 읽기 goroutine 시작
	go readTracePipe()

	// 포트 블로커 생성
	portBlocker := NewPortBlocker(objs.BlockedPorts, logChan)

	// HTTP 서버 설정
	http.HandleFunc("/block", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		portStr := r.URL.Query().Get("port")
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			http.Error(w, "Invalid port number", http.StatusBadRequest)
			return
		}

		if err := portBlocker.BlockPort(uint16(port)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		fmt.Fprintf(w, "Port %d has been blocked\n", port)
	})

	http.HandleFunc("/unblock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		portStr := r.URL.Query().Get("port")
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			http.Error(w, "Invalid port number", http.StatusBadRequest)
			return
		}

		if err := portBlocker.UnblockPort(uint16(port)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		fmt.Fprintf(w, "Port %d has been unblocked\n", port)
	})

	http.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		blockedPorts := portBlocker.GetBlockedPorts()
		fmt.Fprintf(w, "Blocked ports: %v\n", blockedPorts)
	})

	// HTTP 서버 시작
	serverCh := make(chan error, 1)
	go func() {
		log.Println("Starting HTTP server on :8080")
		serverCh <- http.ListenAndServe(":8080", nil)
	}()

	// 종료 시그널 처리
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverCh:
		log.Fatalf("HTTP server error: %v", err)
	case sig := <-signalCh:
		log.Printf("Received signal %v, shutting down", sig)
	}
}