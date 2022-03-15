package shim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/oci"
	"github.com/s3rj1k/go-fanotify/fanotify"
	"golang.org/x/sys/unix"
)

type containerNotifier struct {
	notifyFD   *fanotify.NotifyFD
	firstEvent bool
	sha256Sums map[string]string
	ociSpec    *oci.Spec
	rootFSPath string
	name       string
}

func findContainer(cnts []containerd.Container, cntid string) *containerd.Container {
	for _, cnt := range cnts {
		if cnt.ID() == cntid {
			return &cnt
		}
	}

	return nil
}

func getOCISpec() (*oci.Spec, error) {
	client, err := containerd.New(addressFlag, containerd.WithDefaultNamespace(namespaceFlag))
	if err != nil {
		return nil, fmt.Errorf("creating containerd client: %w", err)
	}
	defer client.Close()

	ctx := context.Background()

	cnts, err := client.Containers(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}

	if len(cnts) == 0 {
		return nil, fmt.Errorf("no container found")
	}

	cntPtr := findContainer(cnts, id)
	if cntPtr == nil {
		return nil, fmt.Errorf("could not find the container with container id: %s", id)
	}

	cnt := *cntPtr

	cntSpec, err := cnt.Spec(context.Background())
	if err != nil {
		return nil, fmt.Errorf("getting container spec: %w", err)
	}

	return cntSpec, nil
}

func getpid() (int, error) {
	// TODO: There is a way to get a pid of the init one using some API. Here is a crude way of doing it.
	cwd, err := os.Getwd()
	if err != nil {
		return 0, fmt.Errorf("getting current working dir: %w", err)
	}

	var data []byte
	initPidFile := cwd + "/init.pid"

	for {
		data, err = os.ReadFile(initPidFile)
		// Wait until the file is created.
		if err != nil && os.IsNotExist(err) {
			continue
		} else if err != nil {
			return 0, fmt.Errorf("reading the init file: %w", err)
		}

		break
	}

	return strconv.Atoi(string(data))
}

func newContainerNotifier() (*containerNotifier, error) {
	oci, err := getOCISpec()
	if err != nil {
		return nil, fmt.Errorf("getting containerd definition of container: %v", err)
	}

	fanotifyFlags := uint(unix.FAN_CLASS_CONTENT | unix.FAN_UNLIMITED_QUEUE | unix.FAN_UNLIMITED_MARKS)
	openFlags := os.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC

	containerNotify, err := fanotify.Initialize(fanotifyFlags, openFlags)
	if err != nil {
		return nil, err
	}

	pid, err := getpid()
	if err != nil {
		return nil, fmt.Errorf("getting PID 1 of the container: %w", err)
	}

	name := namespaceFlag + "/" + id

	n := &containerNotifier{
		firstEvent: true,
		sha256Sums: make(map[string]string),
		notifyFD:   containerNotify,
		rootFSPath: fmt.Sprintf("/proc/%d/root", pid),
		name:       name,
		ociSpec:    oci,
	}

	markPaths := []string{n.rootFSPath}

	// ctx := context.Background()

	for _, mnt := range oci.Mounts {
		// log.G(ctx).Infof("got this mount path: %+v", mnt)

		// Ignore list
		switch mnt.Destination {
		case "/etc/resolv.conf", "/etc/hostname", "/etc/hosts", "/dev/shm", "/var/run/secrets/kubernetes.io/serviceaccount", "/dev/termination-log":
			continue
		}

		// Also mark the host mounted dirs.
		if mnt.Type == "bind" || mnt.Type == "none" {
			markPaths = append(markPaths, mnt.Source)
		}
	}

	if err := n.markDirs(markPaths); err != nil {
		return nil, fmt.Errorf("marking paths: %w", err)
	}

	return n, nil
}

func (n *containerNotifier) markDirs(paths []string) error {
	ctx := context.Background()

	for _, path := range paths {
		err := n.notifyFD.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, unix.FAN_OPEN_EXEC_PERM|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, path)
		if err != nil {
			log.G(ctx).Infof("Marking %s: %s", path, err)
			return err
		}

		log.G(ctx).Infof("Marking %s: done", path)
	}

	return nil
}

// path looks like this: /proc/49190/root/usr/bin/touch
func (n *containerNotifier) ignoreMountPath(path string) bool {
	// Here the path looks like: /usr/bin/touch
	path = strings.TrimPrefix(path, n.rootFSPath)

	for _, mnt := range n.ociSpec.Mounts {
		// Check if the path starts with one of the mount paths.
		if strings.HasPrefix(path, mnt.Destination) {
			return true
		}
	}

	return false
}

func (n *containerNotifier) handleEvent(data *fanotify.EventMetadata, mutex *sync.Mutex) {
	if data == nil {
		return
	}
	defer data.Close()

	ctx := context.Background()

	mutex.Lock()
	// TODO: What if the container was already started, so any modifications done to the container FS won't be encountered here.
	if n.firstEvent {
		log.G(ctx).Infof("first notification received, walking over %s", n.rootFSPath)

		// Make a list of all the executables in the rootfs and create a map of file path and its SHA256
		// store this map in the object.
		// NOTE: If there is no trailing front slash then this function does not walk on the dir.
		err := filepath.WalkDir(n.rootFSPath+"/",
			func(path string, dirEntry os.DirEntry, err error) error {
				if err != nil && os.IsNotExist(err) {
					return nil
				} else if err != nil {
					return fmt.Errorf("default error: %v", err)
				}

				// Figure out if the file is not a dir.
				// Calculate its SHA256sum.
				if dirEntry.IsDir() {
					return nil
				}

				info, err := dirEntry.Info()
				if err != nil && os.IsNotExist(err) {
					return nil
				} else if err != nil {
					return fmt.Errorf("getting info: %w", err)
				}

				// Ignore the mounted volumes checks.
				if n.ignoreMountPath(path) {
					return nil
				}

				// Ignore sym-links.
				if info.Mode()&fs.ModeSymlink != 0 {
					return nil
				}

				// Check if the file is neither user executabe (0100) nor group executable (0010) nor other executable (0001).
				// We don't have any concern for non-executables.
				if !(info.Mode()&0100 != 0 || info.Mode()&0010 != 0 || info.Mode()&0001 != 0) {
					return nil
				}

				sha256sum, err := calculateSHA256Sum(path)
				if err != nil {
					return fmt.Errorf("calculating sha256sum of %s: %w", path, err)
				}

				n.sha256Sums[path] = sha256sum

				return nil
			})
		if err != nil {
			mutex.Unlock()

			log.G(ctx).WithError(err).Fatalf("walking the container rootfs")
		}

		n.firstEvent = false
	}
	mutex.Unlock()

	// The path will look like this:
	// /usr/bin/touch
	path, err := data.GetPath()
	if err != nil {
		log.G(ctx).WithError(err).Fatalf("getting file path")
	}

	// This will look something like this:
	// /proc/49190/root/usr/bin/touch
	path = filepath.Join(n.rootFSPath, path)

	currentSum, err := calculateSHA256SumWithFileObject(data.File())
	if err != nil {
		log.G(ctx).WithError(err).Errorf("calculating sha256sum of %s", path)
		log.G(ctx).Infof("[DENY]:%s: %s", n.name, path)
		n.notifyFD.ResponseDeny(data)
		return
	}

	predeterminedSum, ok := n.sha256Sums[path]
	if !ok {
		// This means it is a new file that is called for execution so deny it.
		log.G(ctx).Infof("[DENY]:%s: %s", n.name, path)
		n.notifyFD.ResponseDeny(data)
		return
	}

	if predeterminedSum != currentSum {
		// This means that the file was modified.
		log.G(ctx).Infof("[DENY]:%s: %s", n.name, path)
		n.notifyFD.ResponseDeny(data)
		return
	}

	log.G(ctx).Infof("[ALLOW]:%s: %s", n.name, path)
	n.notifyFD.ResponseAllow(data)
}

func calculateSHA256Sum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	return calculateSHA256SumWithFileObject(f)
}

func calculateSHA256SumWithFileObject(f *os.File) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("copying data: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// This will be called as a goroutine.
func watchContainerFANotifyEvents() {
	ctx := context.Background()

	notifier, err := newContainerNotifier()
	if err != nil {
		log.G(ctx).WithError(err).Fatal("creating notifier")
	}

	var mutex *sync.Mutex = new(sync.Mutex)
	for {
		// This is a blocking call.
		data, err := notifier.notifyFD.GetEvent(os.Getpid())
		if err != nil {
			log.G(ctx).WithError(err).Fatal("getting event")
		}

		go notifier.handleEvent(data, mutex)
	}
}
