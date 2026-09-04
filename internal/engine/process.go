package engine

import "sync"

// startedProcess separates process creation from waiting. On Linux the
// platform start function keeps the OS thread which called cmd.Start alive
// until wait returns; on platforms without Pdeathsig, waitProcess simply calls
// cmd.Wait directly.
type startedProcess struct {
	release func()
	wait    func() error

	once sync.Once
	done chan struct{}
	err  error
}

func newStartedProcess(release func(), wait func() error) *startedProcess {
	return &startedProcess{release: release, wait: wait, done: make(chan struct{})}
}

// Wait releases any post-start registration barrier exactly once and returns
// the cached process result. It is safe for more than one observer, although
// current runtime ownership uses exactly one waiter.
func (process *startedProcess) Wait() error {
	process.once.Do(func() {
		if process.release != nil {
			process.release()
		}
		process.err = process.wait()
		close(process.done)
	})
	<-process.done
	return process.err
}
