package collector

import "github.com/locktivity/epack/componentsdk"

// gapLog records the collector's gaps, as the epack collectors' gap logs do.
type gapLog struct {
	rec *componentsdk.Recorder
}

func (l gapLog) notCollected(err error, pointer string) {
	l.rec.Helper()
	l.rec.NotCollected(componentsdk.Location{Path: artifactPath, Pointer: pointer}, err)
}
