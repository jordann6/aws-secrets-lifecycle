package sweep

import (
	"strconv"
	"time"
)

// FinishRecord fills derived fields shared by every sweeper: keys,
// effective age (honoring the simulated-age tag for demo data), and
// the scan stamp.
func FinishRecord(r *Record, scanID string, now time.Time) {
	r.ScanID = scanID
	r.ScannedAt = now
	r.PK = r.ARN
	r.SK = "INVENTORY#" + scanID

	age := int64(now.Sub(r.CreatedAt).Hours() / 24)
	if v, ok := r.Tags[simulatedAgeTag]; ok {
		if days, err := strconv.ParseInt(v, 10, 64); err == nil {
			age = days
			r.AgeSimulated = true
			r.CreatedAt = now.AddDate(0, 0, int(-days))
		}
	}
	if age < 0 {
		age = 0
	}
	r.AgeDays = age
}
