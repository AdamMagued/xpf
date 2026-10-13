package flowexport

import "hash/fnv"

// stableExporterID maps an exporter group's config identity
// (protocol, sampling-instance name, referenced template name, address family)
// to a stable, nonzero 32-bit id used as the NetFlow v9 header SourceID
// (RFC 3954 §5.1) and the IPFIX header Observation Domain ID
// (RFC 7011 §3.1). It mirrors config.StableTunnelEndpointID / #1873:
// FNV-1a 64 over the protocol, instance and template joined by "|", each
// field backslash-escaped (`\` → `\\`, `|` → `\|`), plus a literal "|v6"
// suffix for inet6; xor-folded to 32 bits, mapped into [1, 0xFFFFFFFF].
//
// WHY (#3740, #6811, #12148): #3740 gave each (instance, template) group
// a stable id, but groups then contained both address families. #6811 split
// groups by family to prevent cross-family export; this made one inet group
// and one inet6 group with the same (instance, template, collector) compute
// the same id. NetFlow v9 collectors commonly key streams on (exporter source
// IP, SourceID), so independent v9 sequence streams could be mistaken for
// packet loss or exporter restarts. A family suffix gives each group its own
// observation domain; template IDs 256/257 can remain conventional because
// 256 under ODID-A is a different template from 256 under ODID-B.
//
// HA symmetry (the load-bearing constraint): flow export is NOT gated on
// RG mastership — both cluster nodes run exporters from the same synced
// config. Because the id is a pure function of config-synced fields
// (protocol/instance/template/family) and of NOTHING node-specific, both
// nodes compute the IDENTICAL id for a given group, so a failover never
// presents the collector a new observation domain. This is the same
// HA-symmetry argument #1873 relies on, satisfied by construction.
//
// The protocol tag ("netflow9" vs "ipfix") is folded in so a v9 group
// and an IPFIX group with the same instance/template never share a value
// (belt-and-braces; a flow-server binds one version per #2136, so they
// never actually co-point).
//
// Degenerate-default guard: a hand-built ExportConfig{} (the singular
// Build* helpers and several unit tests) carries no instance AND no
// template. The inet default keeps the historical SourceID/ODID = 1 (some
// collectors treat ODID 0 specially). An inet6 group still gets its family
// suffix so it cannot share an id with a same-identity inet group. Real
// multi-group configs always carry a non-empty InstanceName (sampling
// instances are named).
//
// ID migration (#12148): inet ids are unchanged; only inet6 ids change to
// their family-suffixed hash. Collectors therefore see a new v9 SourceID /
// IPFIX ODID for each inet6 group after upgrade. This separates the v9
// sequence streams; collectors or dashboards keyed by the former inet6 id
// may need their filters updated. Templates are re-announced automatically.
//
// Escaping (#12542): instance/template names may literally contain `|`
// (quoted config strings pass through; no charset gate), so the unescaped
// join was byte-ambiguous: inet template `t|v6` hashed identically to inet6
// template `t` (both 3185142171), and inet instance `i|t` with template `v6`
// hashed identically to inet6 instance `i` with template `t`. With every
// field escaped, each unescaped `|` is a separator, so name content cannot
// forge a field boundary or the family suffix. Names without `|` or `\`
// hash exactly as before (the #12148 inet pins hold); names containing `|`
// (previously ambiguous) or `\` (the escape character) get new ids.
func stableExporterID(protocol, instance, template string, isV6 bool) uint32 {
	if instance == "" && template == "" && !isV6 {
		return 1
	}
	// One Write over a stack-built key keeps a typical call free of heap
	// allocation (TestStableExporterIDZeroAlloc12542); a key longer than
	// the buffer spills to the heap with the same bytes, so the same id.
	var buf [128]byte
	b := appendEscapedField(buf[:0], protocol)
	b = append(b, '|')
	b = appendEscapedField(b, instance)
	b = append(b, '|')
	b = appendEscapedField(b, template)
	if isV6 {
		b = append(b, "|v6"...)
	}
	h := fnv.New64a()
	_, _ = h.Write(b)
	s := h.Sum64()
	folded := uint32(s) ^ uint32(s>>32)
	return folded%0xFFFFFFFF + 1
}

// appendEscapedField appends s to b, escaping `\` as `\\` and `|` as `\|`
// (#12542), so field content cannot forge the `|` separator or the `|v6`
// family suffix.
func appendEscapedField(b []byte, s string) []byte {
	for i := range len(s) {
		c := s[i]
		if c == '\\' || c == '|' {
			b = append(b, '\\')
		}
		b = append(b, c)
	}
	return b
}
