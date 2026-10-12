package plugin

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func (a *App) fetchQuota(req request) (pluginapi.QuotaFetchResponse, error) {
	c, err := credentialFrom(req.StorageJSON, req.Metadata)
	if err != nil {
		return pluginapi.QuotaFetchResponse{}, err
	}
	user, err := a.userInfo(c, req.CallbackID)
	if err != nil {
		return pluginapi.QuotaFetchResponse{}, err
	}
	plan := user.PlanV3
	if plan == "" {
		plan = user.PlanV2
	}
	if plan == "" {
		plan = user.Plan
	}
	result := pluginapi.QuotaFetchResponse{}
	if plan != "" {
		result.Subscription = &pluginapi.QuotaSubscription{Plan: plan, TierName: plan}
	}
	buckets := make([]pluginapi.QuotaBucket, 0, 2)
	if bucket, metric, ok := zedQuotaBucket("model_requests", "Model requests", user.ModelUsed, user.ModelLimit); ok {
		if bucket.Window != "" {
			buckets = append(buckets, bucket)
		}
		result.Summary = append(result.Summary, metric...)
	}
	if bucket, metric, ok := zedQuotaBucket("edit_predictions", "Edit predictions", user.EditUsed, user.EditLimit); ok {
		if bucket.Window != "" {
			buckets = append(buckets, bucket)
		}
		result.Summary = append(result.Summary, metric...)
	}
	if len(buckets) > 0 {
		result.Groups = []pluginapi.QuotaGroup{{DisplayName: "Zed Cloud usage", Buckets: buckets}}
	}
	return result, nil
}

func zedQuotaBucket(key, label string, used *int64, rawLimit any) (pluginapi.QuotaBucket, []pluginapi.QuotaMetric, bool) {
	limit, limited := quotaLimit(rawLimit)
	if used == nil {
		return pluginapi.QuotaBucket{}, nil, false
	}
	usedValue := max(0, *used)
	metrics := []pluginapi.QuotaMetric{{Key: key + "_used", Label: label + " used", Value: float64(usedValue)}}
	if !limited {
		return pluginapi.QuotaBucket{}, metrics, true
	}
	metrics = append(metrics, pluginapi.QuotaMetric{Key: key + "_limit", Label: label + " limit", Value: float64(limit)})
	fraction := 1.0
	if limit > 0 {
		fraction = math.Max(0, math.Min(1, float64(limit-usedValue)/float64(limit)))
	} else {
		fraction = 0
	}
	return pluginapi.QuotaBucket{Window: key, RemainingFraction: fraction, Description: label}, metrics, true
}

func quotaLimit(value any) (int64, bool) {
	if object, ok := value.(map[string]any); ok {
		value = object["limited"]
	}
	switch n := value.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil && i >= 0
	case float64:
		return int64(n), n >= 0 && n < float64(math.MaxInt64) && math.Trunc(n) == n
	case int64:
		return n, n >= 0
	case int:
		return int64(n), n >= 0
	case string:
		if strings.EqualFold(strings.TrimSpace(n), "unlimited") {
			return 0, false
		}
		parsed, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64)
		return parsed, err == nil && parsed >= 0
	default:
		return 0, false
	}
}
