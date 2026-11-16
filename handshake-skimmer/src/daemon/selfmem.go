package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

// selfLoadBase finds the runtime load address of this process's own
// executable by scanning /proc/self/maps for the lowest-address mapping
// backed by /proc/self/exe's resolved path. Reading your own maps/mem never
// requires any special capability -- the kernel's ptrace-permission check
// is trivially satisfied when the target is the calling process itself.
func selfLoadBase() (uint64, error) {
	exePath, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return 0, err
	}

	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return 0, err
	}

	base := uint64(math.MaxUint64)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[5] != exePath {
			continue
		}
		addrRange := strings.SplitN(fields[0], "-", 2)
		if len(addrRange) != 2 {
			continue
		}
		start, err := strconv.ParseUint(addrRange[0], 16, 64)
		if err != nil {
			continue
		}
		if start < base {
			base = start
		}
	}
	if base == math.MaxUint64 {
		return 0, fmt.Errorf("could not determine load base")
	}
	return base, nil
}

// validateRange confirms [addr, addr+length) lies entirely within some
// readable mapping of this process, so a bad offset/len causes a clean
// rejection instead of a read fault.
func validateRange(addr uint64, length int) (bool, error) {
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return false, err
	}

	end := addr + uint64(length)
	if end < addr {
		return false, fmt.Errorf("offset/len overflow")
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addrRange := strings.SplitN(fields[0], "-", 2)
		if len(addrRange) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(addrRange[0], 16, 64)
		mapEnd, err2 := strconv.ParseUint(addrRange[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		perms := fields[1]
		if len(perms) > 0 && perms[0] == 'r' && addr >= start && end <= mapEnd {
			return true, nil
		}
	}
	return false, nil
}
