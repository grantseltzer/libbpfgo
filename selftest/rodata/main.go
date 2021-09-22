package main

import "C"

import (
	"os"
	"syscall"
	"unsafe"

	"encoding/binary"
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	rodata, err := bpfModule.GetRODataMap()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	x := struct{ value int }{9001}

	err = rodata.UpdateReadonly(unsafe.Pointer(&x), int(unsafe.Sizeof(x)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	prog, err := bpfModule.GetProgram("kprobe__sys_mmap")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = prog.AttachKprobe("__x64_sys_mmap")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	pb.Start()

	numberOfEventsReceived := 0
	go func() {
		for {
			syscall.Mmap(999, 999, 999, 1, 1)
		}
	}()

recvLoop:
	for {
		b := <-eventsChannel
		fmt.Println(binary.LittleEndian.Uint32(b))

		if binary.LittleEndian.Uint32(b) != 9001 {
			fmt.Println(binary.LittleEndian.Uint32(b))
			fmt.Fprintf(os.Stderr, "invalid data retrieved\n")
			os.Exit(-1)
		}
		numberOfEventsReceived++
		if numberOfEventsReceived > 5 {
			break recvLoop
		}
	}

	// Test that it won't cause a panic or block if Stop or Close called multiple times
	pb.Stop()
	pb.Close()
}
