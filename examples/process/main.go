package main

import (
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf process.c -- -I../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	if len(os.Args) < 3 {
		log.Fatalf("Please specify a process")
	}

	if len(os.Args) < 4 {
		log.Fatalf("Please specify a port")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	objs := bpfObjects{}
	// Load pre-compiled programs into the kernel.
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	process := os.Args[2]

	port, err := strconv.Atoi(os.Args[3])
	if err != nil {
		log.Fatalf("error here: %s", err)
	}

	bpfProg, err := loadBpf()
	if err != nil {
		log.Fatalf("error here: %s", err)
	}

	err = bpfProg.RewriteConstants(map[string]interface{}{
		"process": process,
		"port":    port,
	})
	if err != nil {
		log.Fatalf("error here: %s", err)
	}

	// // add process name to ebpf map
	// err = addPortToMap(objs.ProcessNames, process)
	// if err != nil {
	// 	log.Fatalf("error here: %s", err)
	// }

	// // add port name to ebpf map
	// err = addPortToMap(objs.PortNames, port)
	// if err != nil {
	// 	log.Fatalf("error here: %s", err)
	// }

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.AllowSpecificPort,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
}

// func addPortToMap(m *ebpf.Map, port interface{}) error {
// 	err := m.Put(1, port)
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }
