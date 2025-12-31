//go:build windows

package service

import (
        "context"
        "log"
        "os"
        "sync"
        "time"

        "golang.org/x/sys/windows/svc"
)

type AgentService struct {
        runFunc func(ctx context.Context)
        ctx     context.Context
        cancel  context.CancelFunc
        wg      sync.WaitGroup
}

func NewAgentService(runFunc func(ctx context.Context)) *AgentService {
        return &AgentService{
                runFunc: runFunc,
        }
}

func (s *AgentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
        const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

        changes <- svc.Status{State: svc.StartPending}

        s.ctx, s.cancel = context.WithCancel(context.Background())

        // Channel to detect if runFunc exits prematurely
        runDone := make(chan struct{})
        
        s.wg.Add(1)
        go func() {
                defer s.wg.Done()
                defer close(runDone)
                s.runFunc(s.ctx)
        }()

        changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
        log.Printf("Windows service started successfully")

        for {
                select {
                case c := <-r:
                        switch c.Cmd {
                        case svc.Interrogate:
                                changes <- c.CurrentStatus
                                time.Sleep(100 * time.Millisecond)
                                changes <- c.CurrentStatus
                        case svc.Stop, svc.Shutdown:
                                log.Printf("Windows service received stop/shutdown signal")
                                changes <- svc.Status{State: svc.StopPending}
                                s.cancel()
                                s.wg.Wait()
                                changes <- svc.Status{State: svc.Stopped}
                                return
                        default:
                                log.Printf("unexpected control request #%d", c)
                        }
                case <-runDone:
                        // runFunc exited prematurely (config error, etc.)
                        log.Printf("Windows service runFunc exited unexpectedly, stopping service")
                        changes <- svc.Status{State: svc.StopPending}
                        s.cancel()
                        s.wg.Wait()
                        changes <- svc.Status{State: svc.Stopped}
                        return
                case <-s.ctx.Done():
                        changes <- svc.Status{State: svc.Stopped}
                        return
                }
        }
}

func IsWindowsService() bool {
        isService, err := svc.IsWindowsService()
        if err != nil {
                log.Printf("failed to determine if running as Windows service: %v", err)
                return false
        }
        return isService
}

func RunAsService(name string, runFunc func(ctx context.Context)) error {
        log.Printf("Starting as Windows service: %s", name)
        
        log.Printf("Starting " + name + " service")
        
        err := svc.Run(name, NewAgentService(runFunc))
        if err != nil {
                log.Printf("Service failed: " + err.Error())
                return err
        }
        
        log.Printf(name + " service stopped")
        return nil
}

func init() {
        log.SetOutput(os.Stdout)
        log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}
