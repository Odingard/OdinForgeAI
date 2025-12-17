package sender

import (
        "bytes"
        "compress/gzip"
        "context"
        "encoding/json"
        "errors"
        "io"
        "net/http"
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

func (s *Sender) postBatch(ctx context.Context, events []json.RawMessage) error {
        url := strings.TrimRight(s.cfg.Server.URL, "/") + "/api/agents/events"

        bodyObj := map[string]interface{}{
                "tenant_id": s.cfg.Auth.TenantID,
                "events":    events,
        }
        raw, _ := json.Marshal(bodyObj)

        var body io.Reader
        var contentEncoding string

        if s.cfg.Transport.Compress {
                var buf bytes.Buffer
                gz := gzip.NewWriter(&buf)
                _, _ = gz.Write(raw)
                _ = gz.Close()
                body = bytes.NewReader(buf.Bytes())
                contentEncoding = "gzip"
        } else {
                body = bytes.NewReader(raw)
        }

        req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
        if contentEncoding != "" {
                req.Header.Set("Content-Encoding", contentEncoding)
        }

        req.Header.Set("Content-Type", "application/json")

        // Auth: API key (fallback) or mTLS-only (recommended)
        if strings.EqualFold(s.cfg.Auth.Mode, "api_key") && s.cfg.Auth.APIKey != "" {
                req.Header.Set("Authorization", "Bearer "+s.cfg.Auth.APIKey)
        }

        // Simple retry with backoff + jitter-ish
        backoff := 1 * time.Second
        for attempt := 0; attempt < 5; attempt++ {
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
