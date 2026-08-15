package repository

import (
	"strings"
	"testing"
)

func TestOpsRequestDetailsSLAPredicate(t *testing.T) {
	const businessLimitedFilter = "NOT o.is_business_limited"
	const countTokensFilter = "o.is_count_tokens = FALSE"

	if got := opsRequestDetailsSLAPredicate(false); got != "" {
		t.Fatalf("regular error details must stay unscoped, got %q", got)
	}

	got := opsRequestDetailsSLAPredicate(true)
	if !strings.Contains(got, businessLimitedFilter) {
		t.Fatalf("SLA details must exclude business-limited errors, got %q", got)
	}
	if !strings.Contains(got, countTokensFilter) {
		t.Fatalf("SLA details must exclude count_tokens probes, got %q", got)
	}
}
