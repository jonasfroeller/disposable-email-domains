package domain

import (
	"bufio"
	"errors"
	"net/mail"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"disposable-email-domains/internal/metrics"

	"golang.org/x/net/publicsuffix"
)

// Loads and evaluates allow/block lists and provides PSL-based domain checks.
type Checker struct {
	allowPath string
	blockPath string

	mu        sync.RWMutex
	allow     map[string]struct{}
	block     map[string]struct{}
	rawAllow  []string
	rawBlock  []string
	updatedAt time.Time
	loaded    bool
}

func NewChecker(allowPath, blockPath string) *Checker {
	return &Checker{
		allowPath: allowPath,
		blockPath: blockPath,
	}
}

// PatchBlock incrementally adds new blocklist domains to the in-memory indexes without
// re-reading the underlying file. It assumes the canonical file has already been
// atomically updated (append / rewrite) by the caller. Domains are normalized to
// lowercase and trimmed; empty or comment lines are ignored. Duplicate entries are
// skipped. updatedAt is refreshed only if at least one new domain was inserted.
func (c *Checker) PatchBlock(domains []string) {
	if len(domains) == 0 {
		return
	}
	c.mu.Lock()
	if c.block == nil { // in case Load was never called yet; be defensive
		c.block = make(map[string]struct{})
	}
	inserted := 0
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || strings.HasPrefix(d, "#") {
			continue
		}
		if _, exists := c.block[d]; exists {
			continue
		}
		c.block[d] = struct{}{}
		c.rawBlock = append(c.rawBlock, d)
		inserted++
	}
	if inserted > 0 {
		c.updatedAt = time.Now().UTC()
		if !c.loaded { // mark ready if first successful patch before Load
			c.loaded = true
		}
		metrics.BlocklistSizeGauge.Set(float64(len(c.block)))
	}
	c.mu.Unlock()
}

// Reads the allow/block files into memory (lowercased, trimmed) and updates indexes.
func (c *Checker) Load() error {
	if err := ensureFileExists(c.allowPath, "# allowlist\n"); err != nil {
		return err
	}
	if err := ensureFileExists(c.blockPath, "# blocklist\n"); err != nil {
		return err
	}

	allow, rawAllow, err := readListFile(c.allowPath)
	if err != nil {
		return err
	}
	block, rawBlock, err := readListFile(c.blockPath)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.allow = allow
	c.block = block
	c.rawAllow = rawAllow
	c.rawBlock = rawBlock
	c.updatedAt = time.Now().UTC()
	c.loaded = true
	metrics.BlocklistSizeGauge.Set(float64(len(block)))
	metrics.AllowlistSizeGauge.Set(float64(len(allow)))
	c.mu.Unlock()
	return nil
}

// Returns true if the checker has successfully loaded lists at least once.
func (c *Checker) IsReady() bool {
	c.mu.RLock()
	ready := c.loaded && !c.updatedAt.IsZero()
	c.mu.RUnlock()
	return ready
}

// Returns the number of domains currently in the blocklist map.
func (c *Checker) BlockCount() int {
	c.mu.RLock()
	n := len(c.block)
	c.mu.RUnlock()
	return n
}

// Returns the number of domains currently in the allowlist map.
func (c *Checker) AllowCount() int {
	c.mu.RLock()
	n := len(c.allow)
	c.mu.RUnlock()
	return n
}

func readListFile(path string) (set map[string]struct{}, raw []string, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]struct{}{}, []string{}, nil
		}
		return nil, nil, err
	}
	defer f.Close()
	set = make(map[string]struct{})
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 10*1024*1024) // up to 10MB lines file
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		raw = append(raw, line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		l := strings.ToLower(line)
		set[l] = struct{}{}
	}
	if err := s.Err(); err != nil {
		return nil, nil, err
	}
	return set, raw, nil
}

func ensureFileExists(path, header string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			if !strings.HasSuffix(header, "\n") {
				header += "\n"
			}
			return os.WriteFile(path, []byte(header), 0o644)
		}
		return err
	}
	return nil
}

// Describes the outcome of a domain/email check.
type Result struct {
	Input              string    `json:"input"`
	Type               string    `json:"type"` // "email" or "domain"
	ValidFormat        bool      `json:"valid_format"`
	LocalPart          string    `json:"local_part,omitempty"`
	Domain             string    `json:"domain"`
	NormalizedDomain   string    `json:"normalized_domain"`
	PublicSuffix       string    `json:"public_suffix"`
	RegistrableDomain  string    `json:"registrable_domain"`
	IsPublicSuffixOnly bool      `json:"is_public_suffix_only"`
	IsSubdomain        bool      `json:"is_subdomain"`
	Allowlisted        bool      `json:"allowlisted"`
	Blocklisted        bool      `json:"blocklisted"`
	Status             string    `json:"status"` // one of: allow, block, neutral
	CheckedAt          time.Time `json:"checked_at"`
	UpdatedAt          time.Time `json:"lists_updated_at"`
}

// Check accepts either an email address or bare domain. If email contains '@', it's parsed.
func (c *Checker) Check(input string) Result {
	now := time.Now().UTC()
	res := Result{Input: input, CheckedAt: now}

	// Extract domain from input
	var dom string
	if strings.Contains(input, "@") {
		res.Type = "email"
		addr, err := mail.ParseAddress(input)
		if err == nil {
			// addr.Address may include display name, ensure we take domain after '@'
			parts := strings.Split(addr.Address, "@")
			if len(parts) == 2 {
				res.ValidFormat = true
				res.LocalPart = parts[0]
				dom = parts[1]
			}
		} else {
			// Fallback simple parse
			parts := strings.Split(input, "@")
			if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
				res.ValidFormat = true
				res.LocalPart = parts[0]
				dom = parts[1]
			}
		}
	} else {
		res.Type = "domain"
		res.ValidFormat = true // domain format will be normalized below
		dom = input
	}

	dom = strings.TrimSpace(dom)
	res.Domain = dom
	res.NormalizedDomain = strings.ToLower(dom)

	ps, _ := publicsuffix.PublicSuffix(res.NormalizedDomain)
	etld1, _ := publicsuffix.EffectiveTLDPlusOne(res.NormalizedDomain)
	res.PublicSuffix = ps
	res.RegistrableDomain = etld1
	res.IsPublicSuffixOnly = (ps != "" && ps == res.NormalizedDomain)
	res.IsSubdomain = etld1 != "" && res.NormalizedDomain != etld1

	// Consider both exact domain and registrable domain (eTLD+1) for matching.
	// This makes a list entry for example.com apply to its subdomains as well.
	c.mu.RLock()
	_, allowExact := c.allow[res.NormalizedDomain]
	_, blockExact := c.block[res.NormalizedDomain]
	allowETLD1 := false
	blockETLD1 := false
	if etld1 != "" {
		if _, ok := c.allow[etld1]; ok {
			allowETLD1 = true
		}
		if _, ok := c.block[etld1]; ok {
			blockETLD1 = true
		}
	}
	c.mu.RUnlock()
	allow := allowExact || allowETLD1
	block := blockExact || blockETLD1
	res.Allowlisted = allow
	res.Blocklisted = block
	if allow {
		res.Status = "allow"
	} else if block {
		res.Status = "block"
	} else {
		res.Status = "neutral"
	}

	c.mu.RLock()
	res.UpdatedAt = c.updatedAt
	c.mu.RUnlock()
	return res
}

// Validation summary
type Report struct {
	ErrorsFound         bool      `json:"errors_found"`
	PublicSuffixInBlock []string  `json:"public_suffix_in_blocklist"`
	ThirdLevelInBlock   []string  `json:"third_or_lower_level_in_blocklist"`
	NonLowercaseAllow   []string  `json:"non_lowercase_in_allowlist"`
	NonLowercaseBlock   []string  `json:"non_lowercase_in_blocklist"`
	DuplicatesAllow     []string  `json:"duplicates_in_allowlist"`
	DuplicatesBlock     []string  `json:"duplicates_in_blocklist"`
	UnsortedAllowHint   string    `json:"unsorted_allowlist_hint,omitempty"`
	UnsortedBlockHint   string    `json:"unsorted_blocklist_hint,omitempty"`
	Intersection        []string  `json:"intersection_between_lists"`
	CheckedAt           time.Time `json:"checked_at"`
}

func (c *Checker) Validate() Report {
	c.mu.RLock()
	rawA := append([]string(nil), c.rawAllow...)
	rawB := append([]string(nil), c.rawBlock...)
	c.mu.RUnlock()

	rep := Report{CheckedAt: time.Now().UTC()}

	isSorted := func(lines []string) (bool, string) {
		sorted := append([]string(nil), lines...)
		sort.Strings(sorted)
		for i := 0; i < len(lines) && i < len(sorted); i++ {
			if lines[i] != sorted[i] {
				return false, sorted[i] + " should come before " + lines[i]
			}
		}
		return true, ""
	}

	// Lowercase violations and duplicates for each list (on non-empty, non-comment lines)
	lowerViol := func(lines []string) []string {
		m := make(map[string]struct{})
		var out []string
		for _, l := range lines {
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			if l != strings.ToLower(l) {
				out = append(out, l)
			}
			m[l] = struct{}{}
		}
		return out
	}
	dupes := func(lines []string) []string {
		count := make(map[string]int)
		for _, l := range lines {
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			count[l]++
		}
		var out []string
		for l, n := range count {
			if n > 1 {
				out = append(out, l)
			}
		}
		sort.Strings(out)
		return out
	}

	// Public suffix only and third-level checks for blocklist
	var publicSuffixOnly []string
	var thirdLevel []string
	for _, l := range rawB {
		line := strings.TrimSpace(l)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d := strings.ToLower(line)
		ps, _ := publicsuffix.PublicSuffix(d)
		if ps == d {
			publicSuffixOnly = append(publicSuffixOnly, line)
		}
		if etld1, _ := publicsuffix.EffectiveTLDPlusOne(d); etld1 != "" && etld1 != d {
			thirdLevel = append(thirdLevel, line)
		}
	}

	// Intersections
	c.mu.RLock()
	allowSet := make(map[string]struct{}, len(c.allow))
	for k := range c.allow {
		allowSet[k] = struct{}{}
	}
	var inter []string
	for k := range c.block {
		if _, ok := allowSet[k]; ok {
			inter = append(inter, k)
		}
	}
	c.mu.RUnlock()
	sort.Strings(inter)

	// Sorted hints (non-fatal)
	if ok, hint := isSorted(rawA); !ok {
		rep.UnsortedAllowHint = hint
	}
	if ok, hint := isSorted(rawB); !ok {
		rep.UnsortedBlockHint = hint
	}

	rep.PublicSuffixInBlock = publicSuffixOnly
	rep.ThirdLevelInBlock = thirdLevel
	rep.NonLowercaseAllow = lowerViol(rawA)
	rep.NonLowercaseBlock = lowerViol(rawB)
	rep.DuplicatesAllow = dupes(rawA)
	rep.DuplicatesBlock = dupes(rawB)
	rep.Intersection = inter

	if len(rep.PublicSuffixInBlock) > 0 || len(rep.NonLowercaseAllow) > 0 || len(rep.NonLowercaseBlock) > 0 || len(rep.DuplicatesAllow) > 0 || len(rep.DuplicatesBlock) > 0 || len(rep.Intersection) > 0 {
		rep.ErrorsFound = true
	}
	return rep
}

// Convenience that calls Load and returns an error if validation has fatal issues when strict is true.
func (c *Checker) Reload(strict bool) error {
	if err := c.Load(); err != nil {
		return err
	}
	if !strict {
		return nil
	}
	rep := c.Validate()
	if rep.ErrorsFound {
		return errors.New("list validation errors present")
	}
	return nil
}
