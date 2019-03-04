package clair

import (
	"fmt"
	"time"

	"github.com/coreos/clair/api/v3/clairpb"
	"github.com/genuinetools/reg/registry"
)

// Vulnerabilities scans the given repo and tag using Clair V1 API.
func (c *Clair) Vulnerabilities(r *registry.Registry, repo, tag string) (VulnerabilityReport, error) {
	report := VulnerabilityReport{
		RegistryURL:     r.Domain,
		Repo:            repo,
		Tag:             tag,
		Date:            time.Now().Local().Format(time.RFC1123),
		VulnsBySeverity: make(map[string][]Vulnerability),
	}

	filteredLayers, err := c.getLayers(r, repo, tag, true)
	if err != nil {
		return report, fmt.Errorf("getting filtered layers failed: %v", err)
	}

	if len(filteredLayers) == 0 {
		fmt.Printf("No need to analyse image %s:%s as there is no non-emtpy layer", repo, tag)
		return report, nil
	}

	for i := len(filteredLayers) - 1; i >= 0; i-- {
		// Form the clair layer.
		l, err := c.NewClairLayer(r, repo, filteredLayers, i)
		if err != nil {
			return report, err
		}

		// Post the layer.
		if _, err := c.PostLayer(l); err != nil {
			return report, err
		}
	}

	report.Name = filteredLayers[0].Digest.String()

	vl, err := c.GetLayer(filteredLayers[0].Digest.String(), true, true)
	if err != nil {
		return report, err
	}

	// Get the vulns.
	for _, f := range vl.Features {
		report.Vulns = append(report.Vulns, f.Vulnerabilities...)
	}

	vulnsBy := func(sev string, store map[string][]Vulnerability) []Vulnerability {
		items, found := store[sev]
		if !found {
			items = make([]Vulnerability, 0)
			store[sev] = items
		}
		return items
	}

	// group by severity
	for _, v := range report.Vulns {
		sevRow := vulnsBy(v.Severity, report.VulnsBySeverity)
		report.VulnsBySeverity[v.Severity] = append(sevRow, v)
	}

	// calculate number of bad vulns
	report.BadVulns = len(report.VulnsBySeverity["High"]) + len(report.VulnsBySeverity["Critical"]) + len(report.VulnsBySeverity["Defcon1"])

	return report, nil
}

// VulnerabilitiesV3 scans the given repo and tag using the clair v3 API.
func (c *Clair) VulnerabilitiesV3(r *registry.Registry, repo, tag string) (VulnerabilityReport, error) {
	report := VulnerabilityReport{
		RegistryURL:     r.Domain,
		Repo:            repo,
		Tag:             tag,
		Date:            time.Now().Local().Format(time.RFC1123),
		VulnsBySeverity: make(map[string][]Vulnerability),
	}

	fmt.Printf("Using V3 API %s:%s", repo, tag)
	layers, err := c.getLayers(r, repo, tag, false)
	if err != nil {
		return report, fmt.Errorf("getting filtered layers failed: %v", err)
	}

	if len(layers) == 0 {
		fmt.Printf("No need to analyse image %s:%s as there is no non-empty layer", repo, tag)
		return report, nil
	}

	fmt.Printf("V3 API: found %d layers\n", len(layers))
	report.Name = layers[0].Digest.String()
	clairLayers := []*clairpb.PostAncestryRequest_PostLayer{}
	for i := len(layers) - 1; i >= 0; i-- {
		// Form the clair layer.
		l, err := c.NewClairV3Layer(r, repo, layers[i])
		if err != nil {
			return report, err
		}

		// Append the layer.
		clairLayers = append(clairLayers, l)
	}

	// Post the ancestry.
	if err := c.PostAncestry(layers[0].Digest.String(), clairLayers); err != nil {
		panic(err)
	}

	fmt.Printf("Ancestry Digest=%s\n", layers[0].Digest.String())
	// Get the ancestry.
	vl, err := c.GetAncestry(layers[0].Digest.String())
	if err != nil {
		panic(err)
	}

	if vl == nil {
		panic(err)
	}

	for _, l := range vl.GetLayers() {
		fmt.Printf("layer=%s\n", l.GetLayer().Hash)
		for _, f := range l.GetDetectedFeatures() {
			fmt.Printf("-> %s/%s/%s:%s(%s)\n", f.GetFeatureType(), f.GetNamespace().GetName(), f.GetName(), f.GetVersion(), f.GetVersionFormat())
			for _, v := range f.GetVulnerabilities() {
				fmt.Printf(" -> vuln = %s, fixedby=%s\n", v.GetName(), v.GetFixedBy())
				report.Vulns = append(report.Vulns, Vulnerability{
					Name:          v.Name,
					NamespaceName: v.NamespaceName,
					Description:   v.Description,
					Link:          v.Link,
					Severity:      v.Severity,
					Metadata:      map[string]interface{}{v.Metadata: ""},
					FixedBy:       v.FixedBy,
				})
			}
		}
	}

	vulnsBy := func(sev string, store map[string][]Vulnerability) []Vulnerability {
		items, found := store[sev]
		if !found {
			items = make([]Vulnerability, 0)
			store[sev] = items
		}
		return items
	}

	// Group by severity.
	for _, v := range report.Vulns {
		sevRow := vulnsBy(v.Severity, report.VulnsBySeverity)
		report.VulnsBySeverity[v.Severity] = append(sevRow, v)
	}

	// calculate number of bad vulns
	report.BadVulns = len(report.VulnsBySeverity["High"]) + len(report.VulnsBySeverity["Critical"]) + len(report.VulnsBySeverity["Defcon1"])

	return report, nil
}
