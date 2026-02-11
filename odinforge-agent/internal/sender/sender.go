package sender

import (
        "bytes"
        "compress/gzip"
        "context"
        "encoding/json"
        "errors"
        "fmt"
        "io"
        "net/http"
        "net/url"
        "strings"
        "time"

        "odinforge-agent/internal/config"
        "odinforge-agent/internal/queue"
)

type Sender struct {
        cfg    config.Config
        client *http.Client
}

func New(cfg config.Config) (*Sender, error) {
        tlsCfg, err := BuildTLS(TLSConfig{
                VerifyTLS:  cfg.Server.VerifyTLS,
                CertPath:   cfg.Auth.CertPath,
                KeyPath:    cfg.Auth.KeyPath,
                CAPath:     cfg.Auth.CAPath,
                PinnedSPKI: cfg.Server.PinnedSPKI,
        })
        if err != nil {
                return nil, err
        }

        tr := &http.Transport{
                TLSClientConfig: tlsCfg,
        }

        // Proxy support
        if cfg.Transport.ProxyURL != "" {
                proxyURL, err := url.Parse(cfg.Transport.ProxyURL)
                if err != nil {
                        return nil, fmt.Errorf("invalid proxy URL: %w", err)
                }
                tr.Proxy = http.ProxyURL(proxyURL)
        }

        return &Sender{
                cfg: cfg,
                client: &http.Client{
                        Timeout:   cfg.Transport.Timeout,
                        Transport: tr,
                },
        }, nil
}

func (s *Sender) Flush(ctx context.Context, q *queue.BoltQueue) error {
        depth, _ := q.Depth()
        if depth == 0 {
                return nil
        }

        items, err := q.DequeueBatch(s.cfg.Transport.BatchSize)
        if err != nil {
                return err
        }
        if len(items) == 0 {
                return nil
        }

        keys := make([][]byte, 0, len(items))
        events := make([]json.RawMessage, 0, len(items))

        for _, it := range items {
                keys = append(keys, it.Key)
                events = append(events, json.RawMessage(it.Val))
        }

        err = s.postBatch(ctx, events)
        if err != nil {
                return err
        }

        return q.Ack(keys)
}

// Command represents a queued command from the server
type Command struct {
        ID          string                 `json:"id"`
        CommandType string                 `json:"commandType"`
        Payload     map[string]interface{} `json:"payload,omitempty"`
        Status      string                 `json:"status"`
        CreatedAt   string                 `json:"createdAt"`
        ExpiresAt   string                 `json:"expiresAt,omitempty"`
}

// CommandsResponse is the response from the commands endpoint
type CommandsResponse struct {
        Commands []Command `json:"commands"`
}

// PollCommands fetches pending commands from the server
func (s *Sender) PollCommands(ctx context.Context, agentID string) ([]Command, error) {
        url := strings.TrimRight(s.cfg.Server.URL, "/") + "/api/agents/" + agentID + "/commands"

        req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
        if err != nil {
                return nil, err
        }

        req.Header.Set("X-API-Key", s.cfg.Auth.APIKey)
        req.Header.Set("Content-Type", "application/json")

        resp, err := s.client.Do(req)
        if err != nil {
                return nil, err
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                body, _ := io.ReadAll(resp.Body)
                return nil, errors.New("command poll failed: " + string(body))
        }

        var cmdResp CommandsResponse
        if err := json.NewDecoder(resp.Body).Decode(&cmdResp); err != nil {
                return nil, err
        }

        return cmdResp.Commands, nil
}

// CompleteCommand reports command completion to the server
func (s *Sender) CompleteCommand(ctx context.Context, agentID, commandID string, result map[string]interface{}, errorMsg string) error {
        url := strings.TrimRight(s.cfg.Server.URL, "/") + "/api/agents/" + agentID + "/commands/" + commandID + "/complete"

        body := map[string]interface{}{
                "result": result,
        }
        if errorMsg != "" {
                body["errorMessage"] = errorMsg
        }

        raw, _ := json.Marshal(body)

        req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
        if err != nil {
                return err
        }

        req.Header.Set("X-API-Key", s.cfg.Auth.APIKey)
        req.Header.Set("Content-Type", "application/json")

        resp, err := s.client.Do(req)
        if err != nil {
                return err
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                respBody, _ := io.ReadAll(resp.Body)
                return errors.New("command complete failed: " + string(respBody))
        }

        return nil
}

func (s *Sender) postBatch(ctx context.Context, events []json.RawMessage) error {
        url := strings.TrimRight(s.cfg.Server.URL, "/") + "/api/agents/events"

        bodyObj := map[string]interface{}{
                "tenant_id": s.cfg.Auth.TenantID,
                "events":    events,
        }
        raw, _ := json.Marshal(bodyObj)

        // Prepare compressed body bytes once (if compression enabled)
        var bodyBytes []byte
        var contentEncoding string

        if s.cfg.Transport.Compress {
                var buf bytes.Buffer
                gz := gzip.NewWriter(&buf)
                _, _ = gz.Write(raw)
                _ = gz.Close()
                bodyBytes = buf.Bytes()
                contentEncoding = "gzip"
        } else {
                bodyBytes = raw
        }

        // Simple retry with backoff + jitter-ish
        // NOTE: Create a fresh request on each attempt to avoid consumed body reader issue
        backoff := 1 * time.Second
        for attempt := 0; attempt < 5; attempt++ {
                // Create a new request with fresh body reader on each attempt
                req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
                if err != nil {
                        return err
                }

                if contentEncoding != "" {
                        req.Header.Set("Content-Encoding", contentEncoding)
                }
                req.Header.Set("Content-Type", "application/json")

                // Auth: API key (fallback) or mTLS-only (recommended)
                if strings.EqualFold(s.cfg.Auth.Mode, "api_key") && s.cfg.Auth.APIKey != "" {
                        req.Header.Set("Authorization", "Bearer "+s.cfg.Auth.APIKey)
                }

                resp, err := s.client.Do(req)
                if err == nil && resp != nil {
                        _, _ = io.Copy(io.Discard, resp.Body)
                        _ = resp.Body.Close()
                        if resp.StatusCode >= 200 && resp.StatusCode < 300 {
                                return nil
                        }
                        err = errors.New("server returned " + resp.Status)
                }

                select {
                case <-ctx.Done():
                        return ctx.Err()
                case <-time.After(backoff):
                }
                if backoff < 20*time.Second {
                        backoff *= 2
                }
        }

        return errors.New("failed to deliver batch after retries")
}
