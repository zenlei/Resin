package subscriptionexport

import "strings"

// SubscriptionPath is the public endpoint that serves the generated
// healthy-node subscriptions. Access is controlled by token query param.
const SubscriptionPath = "/api/v1/healthy-node-subscription"

type Format string

const (
	FormatSingbox Format = "singbox"
	FormatClash   Format = "clash"
)

func ParseFormat(raw string) (Format, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "singbox", "sing-box", "json":
		return FormatSingbox, true
	case "clash", "mihomo", "yaml", "yml":
		return FormatClash, true
	default:
		return "", false
	}
}

func (f Format) String() string {
	if f == "" {
		return string(FormatSingbox)
	}
	return string(f)
}

func (f Format) ContentType() string {
	switch f {
	case FormatClash:
		return ContentTypeClash
	default:
		return ContentTypeSingbox
	}
}
