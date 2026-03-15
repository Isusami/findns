package scanner

import (
	"context"
	"math"
	"sort"
	"time"
)

type Metrics map[string]float64

type Result struct {
	IP      string
	OK      bool
	Metrics Metrics
}

type CheckFunc func(ip string, timeout time.Duration) (bool, Metrics)

type ProgressFunc func(done, total, passed, failed int)

func RunPool(ips []string, workers int, timeout time.Duration, check CheckFunc, onProgress ProgressFunc) []Result {
	return RunPoolCtx(context.Background(), ips, workers, timeout, check, onProgress)
}

func RunPoolCtx(ctx context.Context, ips []string, workers int, timeout time.Duration, check CheckFunc, onProgress ProgressFunc) []Result {
	jobs := make(chan string)
	bufSize := workers * 4
	if bufSize > len(ips) {
		bufSize = len(ips)
	}
	results := make(chan Result, bufSize)

	for i := 0; i < workers; i++ {
		go func() {
			for ip := range jobs {
				func() {
					defer func() {
						if r := recover(); r != nil {
							results <- Result{IP: ip, OK: false}
						}
					}()
					ok, m := check(ip, timeout)
					results <- Result{IP: ip, OK: ok, Metrics: m}
				}()
			}
		}()
	}

	go func() {
		for _, ip := range ips {
			select {
			case jobs <- ip:
			case <-ctx.Done():
				close(jobs)
				return
			}
		}
		close(jobs)
	}()

	var pass, fail int
	out := make([]Result, 0, len(ips))
	for i := 0; i < len(ips); i++ {
		select {
		case r := <-results:
			out = append(out, r)
			if r.OK {
				pass++
			} else {
				fail++
			}
			if onProgress != nil {
				onProgress(i+1, len(ips), pass, fail)
			}
		case <-ctx.Done():
			return out
		}
	}
	return out
}

func roundMs(v float64) float64 {
	return math.Round(v*1000) / 1000
}

func SortByMetric(results []Result, key string) {
	sort.SliceStable(results, func(i, j int) bool {
		vi, oki := results[i].Metrics[key]
		vj, okj := results[j].Metrics[key]
		if !oki {
			vi = math.MaxFloat64
		}
		if !okj {
			vj = math.MaxFloat64
		}
		return vi < vj
	})
}
