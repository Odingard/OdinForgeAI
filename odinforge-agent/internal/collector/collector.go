package collector

import (
        "context"
        "time"

        "odinforge-agent/internal/config"
        "odinforge-agent/internal/util"
)

type Event struct {
        ID           string                 `json:"id"`
        Type         string                 `json:"type"` // telemetry|heartbeat
        SchemaVer    int                    `json:"schema_version"`
        TenantID     string                 `json:"tenant_id"`
        AgentID      string                 `json:"agent_id"`
        TimestampUTC time.Time              `json:"timestamp_utc"`
        Payload      map[string]interface{} `json:"payload"`
}

type Collector struct {
        cfg    config.Config
        agent  string
        bootID string
}

func New(cfg config.Config) *Collector {
        agentID := StableAgentID() // deterministic per machine/container where possible
        return &Collector{cfg: cfg, agent: agentID}
}

func (c *Collector) CollectTelemetry(ctx context.Context) (Event, error) {
        sys, err := GetSystemInfo()
        if err != nil {
                return Event{}, err
        }
        met := GetMetrics()
        net := GetNetworkInfo()
        services := GetRunningServices()
        ports := GetOpenPorts()
        container := GetContainerInfo()

        payload := map[string]interface{}{
                "system":    sys,
                "metrics":   met,
                "network":   net,
                "services":  services,
                "ports":     ports,
                "container": container,
        }

        return Event{
                ID:           NewEventID(),
                Type:         "telemetry",
                SchemaVer:    1,
                TenantID:     c.cfg.Auth.TenantID,
                AgentID:      c.agent,
                TimestampUTC: time.Now().UTC(),
                Payload:      payload,
        }, nil
}

// HeartbeatEvent creates a heartbeat event using the collector's cached agent ID
// to ensure stable identity across container restarts.
func (c *Collector) HeartbeatEvent() Event {
        return Event{
                ID:           NewEventID(),
                Type:         "heartbeat",
                SchemaVer:    1,
                TenantID:     c.cfg.Auth.TenantID,
                AgentID:      c.agent,
                TimestampUTC: time.Now().UTC(),
                Payload: map[string]interface{}{
                        "status": "ok",
                },
        }
}

func NewEventID() string {
        return "ev_" + util.RandHex(12)
}
