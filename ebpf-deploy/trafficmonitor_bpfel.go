// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type TrafficMonitorTrafficStats struct {
	Packets  uint64
	Bytes    uint64
	LastSeen uint64
}

// LoadTrafficMonitor returns the embedded CollectionSpec for TrafficMonitor.
func LoadTrafficMonitor() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TrafficMonitorBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load TrafficMonitor: %w", err)
	}

	return spec, err
}

// LoadTrafficMonitorObjects loads TrafficMonitor and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*TrafficMonitorObjects
//	*TrafficMonitorPrograms
//	*TrafficMonitorMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadTrafficMonitorObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadTrafficMonitor()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// TrafficMonitorSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TrafficMonitorSpecs struct {
	TrafficMonitorProgramSpecs
	TrafficMonitorMapSpecs
	TrafficMonitorVariableSpecs
}

// TrafficMonitorProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TrafficMonitorProgramSpecs struct {
	XdpTrafficMonitor *ebpf.ProgramSpec `ebpf:"xdp_traffic_monitor"`
}

// TrafficMonitorMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TrafficMonitorMapSpecs struct {
	PortMap    *ebpf.MapSpec `ebpf:"port_map"`
	Rb         *ebpf.MapSpec `ebpf:"rb"`
	TrafficMap *ebpf.MapSpec `ebpf:"traffic_map"`
}

// TrafficMonitorVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TrafficMonitorVariableSpecs struct {
}

// TrafficMonitorObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadTrafficMonitorObjects or ebpf.CollectionSpec.LoadAndAssign.
type TrafficMonitorObjects struct {
	TrafficMonitorPrograms
	TrafficMonitorMaps
	TrafficMonitorVariables
}

func (o *TrafficMonitorObjects) Close() error {
	return _TrafficMonitorClose(
		&o.TrafficMonitorPrograms,
		&o.TrafficMonitorMaps,
	)
}

// TrafficMonitorMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadTrafficMonitorObjects or ebpf.CollectionSpec.LoadAndAssign.
type TrafficMonitorMaps struct {
	PortMap    *ebpf.Map `ebpf:"port_map"`
	Rb         *ebpf.Map `ebpf:"rb"`
	TrafficMap *ebpf.Map `ebpf:"traffic_map"`
}

func (m *TrafficMonitorMaps) Close() error {
	return _TrafficMonitorClose(
		m.PortMap,
		m.Rb,
		m.TrafficMap,
	)
}

// TrafficMonitorVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to LoadTrafficMonitorObjects or ebpf.CollectionSpec.LoadAndAssign.
type TrafficMonitorVariables struct {
}

// TrafficMonitorPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadTrafficMonitorObjects or ebpf.CollectionSpec.LoadAndAssign.
type TrafficMonitorPrograms struct {
	XdpTrafficMonitor *ebpf.Program `ebpf:"xdp_traffic_monitor"`
}

func (p *TrafficMonitorPrograms) Close() error {
	return _TrafficMonitorClose(
		p.XdpTrafficMonitor,
	)
}

func _TrafficMonitorClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed trafficmonitor_bpfel.o
var _TrafficMonitorBytes []byte
