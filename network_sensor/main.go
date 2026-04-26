//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ebpf/sensor.c

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const tcpEventBinarySize = 28

type tcpEvent struct {
	PID   uint32 `json:"pid"`
	Comm  string `json:"comm"`
	Daddr uint32 `json:"daddr"`
	Dport uint16 `json:"dport"`
}

func decodeTCPEvent(raw []byte) (tcpEvent, error) {
	if len(raw) < tcpEventBinarySize {
		return tcpEvent{}, errors.New("ring buffer record is shorter than expected tcp event size")
	}

	pid := binary.LittleEndian.Uint32(raw[0:4])
	commBytes := raw[4:20]
	daddr := binary.LittleEndian.Uint32(raw[20:24])
	dport := binary.LittleEndian.Uint16(raw[24:26])

	commEnd := 0
	for commEnd < len(commBytes) && commBytes[commEnd] != 0 {
		commEnd++
	}

	return tcpEvent{
		PID:   pid,
		Comm:  string(commBytes[:commEnd]),
		Daddr: daddr,
		Dport: dport,
	}, nil
}

func isExpectedRingBufferClose(err error) bool {
	return errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, net.ErrClosed)
}

func main() {
	// The signal context allows clean exit on SIGINT/SIGTERM without forcing a panic.
	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	var objects bpfObjects
	if err := loadBpfObjects(&objects, nil); err != nil {
		log.Fatalf("failed to load bpf objects: %v", err)
	}
	defer objects.Close()

	// Attach the eBPF kprobe program to the kernel tcp_connect hook point.
	kprobeLink, err := link.Kprobe("tcp_connect", objects.KprobeTcpConnect, nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe tcp_connect: %v", err)
	}
	defer kprobeLink.Close()

	// The reader consumes kernel events from the tcp_events ring buffer map.
	reader, err := ringbuf.NewReader(objects.TcpEvents)
	if err != nil {
		log.Fatalf("failed to create ring buffer reader: %v", err)
	}
	defer reader.Close()

	go func() {
		<-ctx.Done()
		_ = reader.Close()
	}()

	log.Printf("Waiting for events from tcp_events ring buffer...")

	// This loop continuously reads connection events until shutdown is requested.
	for {
		record, err := reader.Read()
		if err != nil {
			if isExpectedRingBufferClose(err) {
				log.Printf("stopping ring buffer reader: %v", err)
				break
			}
			log.Printf("ring buffer read error: %v", err)
			continue
		}

		event, err := decodeTCPEvent(record.RawSample)
		if err != nil {
			log.Printf("failed to decode tcp event: %v", err)
			continue
		}

		// Every decoded event is forwarded to the orchestrator via UDS as JSON.
		if err := SendPayload(event); err != nil {
			log.Printf("failed to send payload to orchestrator: %v", err)
			continue
		}

		log.Printf("forwarded event pid=%d comm=%s daddr=%d dport=%d", event.PID, event.Comm, event.Daddr, event.Dport)
	}
}
