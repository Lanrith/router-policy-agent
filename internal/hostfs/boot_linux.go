package hostfs

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
)

// KernelBootID reads only the fixed read-only procfs boot identifier. Callers
// cannot supply a pathname or restore this observation from runtime JSON.
func KernelBootID(ctx context.Context) (string, error) {
	if ctx == nil {
		return "", errors.New("hostfs: missing boot observation context")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	file, err := os.OpenFile("/proc/sys/kernel/random/boot_id", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	boot, readErr := readKernelBootID(ctx, file)
	if err := errors.Join(readErr, file.Close()); err != nil {
		return "", err
	}
	return boot, nil
}

func readKernelBootID(ctx context.Context, file *os.File) (string, error) {
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 {
		return "", errors.New("hostfs: unsafe kernel boot identifier")
	}
	fd := file.Fd()
	if fd > uintptr(^uint(0)>>1) {
		return "", errors.New("hostfs: invalid kernel boot descriptor")
	}
	var filesystem syscall.Statfs_t
	if err := syscall.Fstatfs(int(fd), &filesystem); err != nil {
		return "", err
	}
	if filesystem.Type != 0x9fa0 { // PROC_SUPER_MAGIC, Linux filesystem ABI.
		return "", errors.New("hostfs: boot identifier is not from procfs")
	}
	if err := checkKernelProcOwner(stat); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(file, 38))
	if err := errors.Join(err, ctx.Err()); err != nil {
		return "", err
	}
	return parseKernelBootID(data)
}

// Procfs's immutable root inode supplies the kernel root owner in the current
// user namespace. Host UID 0 can appear as the overflow UID inside a rootless
// test namespace; accepting an arbitrary numeric overflow owner is unsafe.
func checkKernelProcOwner(file *syscall.Stat_t) (result error) {
	root, err := os.OpenFile("/proc", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	info, err := root.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Ino != 1 || info.Mode().Perm()&0o222 != 0 || stat.Dev != file.Dev || stat.Uid != file.Uid || stat.Gid != file.Gid {
		return errors.New("hostfs: boot identifier is not owned by the kernel procfs root")
	}
	return nil
}

func parseKernelBootID(data []byte) (string, error) {
	if len(data) != 37 || data[36] != '\n' || data[8] != '-' || data[13] != '-' || data[18] != '-' || data[23] != '-' {
		return "", errors.New("hostfs: malformed kernel boot identifier")
	}
	boot := strings.ReplaceAll(string(data[:36]), "-", "")
	decoded, err := hex.DecodeString(boot)
	if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != boot || boot == strings.Repeat("0", 32) {
		return "", errors.New("hostfs: noncanonical kernel boot identifier")
	}
	return boot, nil
}
