package agent

import (
	agentv1 "github.com/FourLeggedLabs/protos/gen/go/censor/agent/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func protoJSONUnmarshal(b []byte, m *agentv1.AgentPolicy) error {
	return protojson.Unmarshal(b, m)
}
