package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"context"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gorilla/mux"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang TrafficMonitor ./ebpf/traffic_monitor.c -- -I./ebpf/headers

// 로그 이벤트 구조체 (eBPF의 log_event와 일치해야 함)
type LogEvent struct {
	SrcIP     uint32    `json:"src_ip"`
	DstIP     uint32    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  uint8     `json:"protocol"`
	Timestamp uint64    `json:"timestamp"`
	Size      uint32    `json:"size"`
	Action    uint8     `json:"action"`
}

// TrafficStats는 포트별 트래픽 통계를 저장하는 구조체입니다.
type TrafficStats struct {
	Packets  uint64    `json:"packets"`
	Bytes    uint64    `json:"bytes"`
	LastSeen uint64    `json:"last_seen"`
}

// HumanLogEvent는 로그 이벤트를 사람이 읽기 쉬운 형태로 변환합니다.
type HumanLogEvent struct {
	Timestamp  string    `json:"timestamp"`
	SrcIP      string    `json:"src_ip"`
	SrcPort    uint16    `json:"src_port"`
	DstIP      string    `json:"dst_ip"`
	DstPort    uint16    `json:"dst_port"`
	Protocol   string    `json:"protocol"`
	Size       uint32    `json:"size"`
	Action     string    `json:"action"`
}

// 로그 이벤트를 사람이 읽기 쉬운 형태로 변환합니다.
func (e *LogEvent) ToHuman() HumanLogEvent {
	srcIP := net.IPv4(
		byte(e.SrcIP),
		byte(e.SrcIP>>8),
		byte(e.SrcIP>>16),
		byte(e.SrcIP>>24),
	).String()
	
	dstIP := net.IPv4(
		byte(e.DstIP),
		byte(e.DstIP>>8),
		byte(e.DstIP>>16),
		byte(e.DstIP>>24),
	).String()
	
	protoName := "Unknown"
	switch e.Protocol {
	case 6:
		protoName = "TCP"
	case 17:
		protoName = "UDP"
	case 1:
		protoName = "ICMP"
	}
	
	timestamp := time.Unix(0, int64(e.Timestamp)).Format(time.RFC3339)
	
	action := "Unknown"
	switch e.Action {
	case 0:
		action = "Pass"
	case 1:
		action = "Block"
	case 2:
		action = "Monitor"
	}
	
	return HumanLogEvent{
		Timestamp: timestamp,
		SrcIP:     srcIP,
		SrcPort:   e.SrcPort,
		DstIP:     dstIP,
		DstPort:   e.DstPort,
		Protocol:  protoName,
		Size:      e.Size,
		Action:    action,
	}
}

func (e *LogEvent) String() string {
	human := e.ToHuman()
	return fmt.Sprintf("[%s] %s:%d -> %s:%d (%s) %d bytes [%s]",
		human.Timestamp,
		human.SrcIP, human.SrcPort,
		human.DstIP, human.DstPort,
		human.Protocol, human.Size,
		human.Action)
}

// PortManager는 포트 필터링 및 모니터링을 관리하는 구조체입니다.
type PortManager struct {
	mu          sync.RWMutex
	portMap     *ebpf.Map
	trafficMap  *ebpf.Map
	managedPorts map[uint16]uint8   // 포트:액션
	logEvents   []LogEvent          // 최근 로그 이벤트 (최대 1000개)
	logChan     chan LogEvent       // 로그 이벤트 채널
	maxLogEvents int                // 최대 저장할 로그 이벤트 수
}

func NewPortManager(portMap, trafficMap *ebpf.Map, maxLogEvents int) *PortManager {
	return &PortManager{
		portMap:     portMap,
		trafficMap:  trafficMap,
		managedPorts: make(map[uint16]uint8),
		logEvents:   make([]LogEvent, 0, maxLogEvents),
		logChan:     make(chan LogEvent, 100),
		maxLogEvents: maxLogEvents,
	}
}

// 포트를 차단하거나 모니터링합니다.
func (pm *PortManager) ManagePort(port uint16, action uint8) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// 이미 같은 액션으로 관리되고 있는지 확인
	if currentAction, exists := pm.managedPorts[port]; exists && currentAction == action {
		return fmt.Errorf("port %d is already managed with action %d", port, action)
	}

	// eBPF 맵에 포트 추가
	if err := pm.portMap.Put(port, action); err != nil {
		return fmt.Errorf("failed to update eBPF map: %v", err)
	}

	// 관리 목록에 추가
	pm.managedPorts[port] = action
	
	actionStr := "blocked"
	if action == 2 {
		actionStr = "monitored"
	}
	
	log.Printf("Port %d is now %s", port, actionStr)
	return nil
}

// 포트 관리를 해제합니다.
func (pm *PortManager) UnmanagePort(port uint16) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// 관리 중인 포트인지 확인
	if _, exists := pm.managedPorts[port]; !exists {
		return fmt.Errorf("port %d is not managed", port)
	}

	// eBPF 맵에서 포트 제거
	if err := pm.portMap.Delete(port); err != nil {
		return fmt.Errorf("failed to delete from eBPF map: %v", err)
	}

	// 관리 목록에서 제거
	delete(pm.managedPorts, port)
	log.Printf("Port %d management has been removed", port)
	return nil
}

// 관리 중인 포트 목록을 반환합니다.
func (pm *PortManager) GetManagedPorts() map[uint16]string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	result := make(map[uint16]string)
	for port, action := range pm.managedPorts {
		if action == 1 {
			result[port] = "Block"
		} else if action == 2 {
			result[port] = "Monitor"
		}
	}
	return result
}

// 트래픽 통계를 가져옵니다.
func (pm *PortManager) GetTrafficStats(port uint16) (*TrafficStats, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var stats TrafficStats
	err := pm.trafficMap.Lookup(port, &stats)
	if err != nil {
		return nil, fmt.Errorf("failed to get traffic stats for port %d: %v", port, err)
	}
	
	return &stats, nil
}

// 모든 포트의 트래픽 통계를 가져옵니다.
func (pm *PortManager) GetAllTrafficStats() (map[uint16]TrafficStats, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	result := make(map[uint16]TrafficStats)
	
	var key uint16
	var stats TrafficStats
	
	iter := pm.trafficMap.Iterate()
	for iter.Next(&key, &stats) {
		result[key] = stats
	}
	
	return result, iter.Err()
}

// 로그 이벤트를 추가합니다.
func (pm *PortManager) AddLogEvent(event LogEvent) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	// 로그 이벤트를 배열 앞에 추가 (최신 이벤트가 앞에 오도록)
	pm.logEvents = append([]LogEvent{event}, pm.logEvents...)
	
	// 최대 로그 이벤트 수를 초과하면 오래된 이벤트 제거
	if len(pm.logEvents) > pm.maxLogEvents {
		pm.logEvents = pm.logEvents[:pm.maxLogEvents]
	}
}

// 로그 이벤트를 가져옵니다.
func (pm *PortManager) GetLogEvents(limit int) []LogEvent {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	if limit <= 0 || limit > len(pm.logEvents) {
		limit = len(pm.logEvents)
	}
	
	return pm.logEvents[:limit]
}

// RingBuffer에서 로그 이벤트를 읽는 함수
func readRingBuffer(rb *ringbuf.Reader, logChan chan LogEvent) {
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
		var event LogEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Failed to parse event: %v", err)
			continue
		}

		// 로그 채널로 이벤트 전송
		logChan <- event
		
		// 또한 로그도 출력
		log.Printf("Packet: %s", event.String())
	}
}

// 로그 처리 함수
func processLogs(pm *PortManager) {
	for event := range pm.logChan {
		pm.AddLogEvent(event)
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
	objs := TrafficMonitorObjects{}
	if err := LoadTrafficMonitorObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// XDP 프로그램을 네트워크 인터페이스에 연결
	ifaceName := "eth0" // 기본값, 사용자 환경에 맞게 수정 가능
	
	// 환경 변수로 인터페이스 이름을 받을 수 있도록 함
	if envIface := os.Getenv("IFACE"); envIface != "" {
		ifaceName = envIface
	}
	
	log.Printf("Attaching XDP program to interface: %s", ifaceName)

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	}

	// generic 모드를 사용하여 XDP 프로그램 연결 시도
	ifaceLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpTrafficMonitor,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // generic 모드 사용
	})
	if err != nil {
		log.Printf("Failed to attach XDP in generic mode: %v", err)
		log.Printf("Falling back to native mode...")
		
		// generic 모드가 실패하면 native 모드로 시도
		ifaceLink, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpTrafficMonitor,
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

	// 포트 매니저 생성 (최대 1000개의 로그 이벤트 저장)
	portManager := NewPortManager(objs.PortMap, objs.TrafficMap, 1000)

	// RingBuffer 읽기 goroutine 시작
	go readRingBuffer(rb, portManager.logChan)
	
	// 로그 처리 goroutine 시작
	go processLogs(portManager)

	// HTTP 라우터 설정
	router := mux.NewRouter()
	
	// API 라우트 설정
	apiRouter := router.PathPrefix("/api").Subrouter()
	
	// 포트 관리 API
	apiRouter.HandleFunc("/manage", func(w http.ResponseWriter, r *http.Request) {
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
		
		actionStr := r.URL.Query().Get("action")
		var action uint8
		
		switch actionStr {
		case "block":
			action = 1
		case "monitor":
			action = 2
		default:
			http.Error(w, "Invalid action. Use 'block' or 'monitor'", http.StatusBadRequest)
			return
		}

		if err := portManager.ManagePort(uint16(port), action); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("Port %d is now managed with action: %s", port, actionStr),
		})
	})

	apiRouter.HandleFunc("/unmanage", func(w http.ResponseWriter, r *http.Request) {
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

		if err := portManager.UnmanagePort(uint16(port)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("Port %d management has been removed", port),
		})
	})

	apiRouter.HandleFunc("/ports", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(portManager.GetManagedPorts())
	})
	
	// 트래픽 통계 API
	apiRouter.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		portStr := r.URL.Query().Get("port")
		if portStr == "" {
			// 모든 포트의 통계 반환
			stats, err := portManager.GetAllTrafficStats()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			
			// 결과 변환
			result := make(map[string]interface{})
			for port, stat := range stats {
				result[fmt.Sprintf("%d", port)] = map[string]interface{}{
					"packets":   stat.Packets,
					"bytes":     stat.Bytes,
					"last_seen": time.Unix(0, int64(stat.LastSeen)).Format(time.RFC3339),
				}
			}
			
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}
		
		// 특정 포트의 통계 반환
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			http.Error(w, "Invalid port number", http.StatusBadRequest)
			return
		}
		
		stats, err := portManager.GetTrafficStats(uint16(port))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"port":      port,
			"packets":   stats.Packets,
			"bytes":     stats.Bytes,
			"last_seen": time.Unix(0, int64(stats.LastSeen)).Format(time.RFC3339),
		})
	})
	
	// 로그 이벤트 API
	apiRouter.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		limitStr := r.URL.Query().Get("limit")
		limit := 100 // 기본값
		
		if limitStr != "" {
			parsedLimit, err := strconv.Atoi(limitStr)
			if err == nil && parsedLimit > 0 {
				limit = parsedLimit
			}
		}
		
		events := portManager.GetLogEvents(limit)
		humanEvents := make([]HumanLogEvent, len(events))
		
		for i, event := range events {
			humanEvents[i] = event.ToHuman()
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(humanEvents)
	})
	
	// HTTP 서버 설정
	server := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// HTTP 서버 시작
	serverCh := make(chan error, 1)
	go func() {
		log.Println("Starting HTTP server on :8080")
		serverCh <- server.ListenAndServe()
	}()

	// 종료 시그널 처리
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverCh:
		log.Fatalf("HTTP server error: %v", err)
	case sig := <-signalCh:
		log.Printf("Received signal %v, shutting down", sig)
		ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}
}