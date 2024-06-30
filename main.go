package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	bpfProgram = `
#include <linux/sched.h>
#include <linux/sched/task.h>
BPF_HASH(stats);

int do_trace(struct pt_regs *ctx) {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u64 *val, zero = 0;

	val = stats.lookup_or_init(&pid, &zero);
	(*val)++;

	return 0;
}
`
)

func main() {
	// Load eBPF program
	bpfModule, err := loadBPFProgram(bpfProgram)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading BPF program: %v\n", err)
		return
	}
	defer bpfModule.Close()

	// Attach eBPF program to tracepoint
	attachErr := attachTracepoint(bpfModule)
	if attachErr != nil {
		fmt.Fprintf(os.Stderr, "Error attaching to tracepoint: %v\n", attachErr)
		return
	}

	// Handle termination signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	// Print stats every 5 seconds
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	stats := make(map[uint32]uint64)

	for {
		select {
		case <-ticker.C:
			printStats(stats)
		case <-sig:
			fmt.Println("\nReceived termination signal. Exiting...")
			return
		}
	}
}

func loadBPFProgram(bpfSource string) (*unix.BPFModule, error) {
	module := unix.NewModule(bpfSource)
	if err := module.Load(nil); err != nil {
		return nil, fmt.Errorf("error loading BPF program: %v", err)
	}
	return module, nil
}

func attachTracepoint(module *unix.BPFModule) error {
	progName := "do_trace"
	tracepoint := fmt.Sprintf("sched/sched_process_exec")

	prog, err := module.LoadProgram(progName, unix.BPFProgramTypeTracepoint)
	if err != nil {
		return fmt.Errorf("error loading BPF trace program: %v", err)
	}

	if err := module.AttachTracepoint(tracepoint, prog); err != nil {
		return fmt.Errorf("error attaching to tracepoint %s: %v", tracepoint, err)
	}

	return nil
}

func printStats(stats map[uint32]uint64) {
	fmt.Println("Process ID\tExecutions")
	for pid, count := range stats {
		fmt.Printf("%d\t\t%d\n", pid, count)
	}
}

