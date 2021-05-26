# Clair Enrichment Specification

Author: Louis DeLosSantos

## Summary

Clair V4 took the initial stance of not providing NVD related metadata.

There are numerous articles on the inaccuracies of NVD

While relying directly on NVD data is not what the Clair team suggests, it can
provide a value as a supplemental metadata source for official upstream repositories.

This specification will outline the use of NVD and other supplemental data sources
as metadata resources; additional information over some characteristics of the vulnerability
report a user may find useful.

Our use of auxillary metadata sources "enrich" our Vulnerabilities and 
Vulnerability Report.

This is the naming convention we will use moving forward.

## Solution

The notion of "Enrichment(s)" will be added to our VulnerabilityReport schema.

An Enrichment is supplemental data for a particular resource, 
be it a vulnerability or a manifest as a whole.

Examples of supplemental data are:

- external gradings and scores on the health of a manifest.
- external severity information for a vulnerability.

Here, external means a data source other then the 
official upstream.

### EnrichmentUpdater

A new interface is introduced into Libvuln's driver package for writing Enrichments 
into Libvuln's vulnstore.

```golang
// EnrichmentRecord is a simple container for JSON Enrichment data
// and the tags it will be queried by.
type EnrichmentRecord struct {
      Tags []string
      Enrichment json.RawMessage
}

// EnrichmentUpdater fetches an Enrichment data source, parses its contents,
// and returns individual EnrichmentRecords.
type EnrichmentUpdater interface {
      // A unique name for this updater.
      // The name preferable indicates the vendor who implemented
      // it and the enrichment data source its fetching and downloading.
      Name() string
      // When called the updater must return an io.ReadCloser to the enrichment data source.
      // and a Fingerprint of this data source.
      FetchEnrichment (context.Context, Fingerprint) (io.ReadCloser, Fingerprint, error)
      // When called the updater must read from the provided io.ReadCloser, parse its contents
      // and return a set of EnrichmentRecord(s)
      ParseEnrichment (context.Context, io.ReadCloser) ([]EnrichmentRecord, error)
}
```

When an EnrichmentUpater's FetchEnrichment method is called an io.ReadCloser is
returned where its enrichment database can be read.

When its ParseEnrichment method is called the EnrichmentUpdater should read the 
io.ReadCloser and return a slice of EnrichmentRecord structs.

An EnrichmentUpdater implementation must do the following for each returned EnrichmentRecord:

- Provide tags by which these EnrichmentRecords may be searched by.
- Provide metdata in the form of serialized json.

Example:

A new NVD EnrichmentUpdater is implemented.
This updater returns a io.ReadCloser where the NVD JSON feed can be read from.
When this updater's Parse method is called it begins reading the JSON feed and
for each JSON object:

- Creates an EnrichmentRecord struct.
- Sets the Tags field to the CVE number associated with this enrichment entry.
- Sets the Enrichment field as the serialized JSON enrichment data.

Discussion Note: Utilizing tags here places us in a position to take advantage
of GIN reverse indexes in Postgres.

### Enricher

Enrichment is the act of "enriching" a VulnerabilityReport with auxillary data.

A new interface is created for this purpose.

This interface works in pair with a EnrichmentUpdater of the same name.

```golang
type Enricher interface {
    // A unique name for this updater.
    // The name preferable indicates the vendor who implemented
    // it and matches the cooresponding EnrichmentUpdater.
    Name() string
    // Enrich extracts a set of tags from the provided VulnerabilityReport and utilizes 
    // the provided EnrichmentGetter to retrieve any Enrichments associated with the query tags.
    //
    // The implemented Enricher returns raw JSON blogs of the retrieved Enrichment data and a key
    // explaining to the client how to interpret the data.
    Enrich(ctx context.Context, e EnrichmentGetter, v *claircore.VulnerabilityReport) (key mime, []json.RawMessage, error)
}
```

Enricher implementations will typically be paired with EnrichmentUpdater implementations.

An Enricher is typically authoritive over a specific enrichment data source, such
as NVD and understands how its paired EnrichmentUpdater tags its data.

An Enricher is linked with an EnrichmentUpdater via their "Name" fields.

When an Enricher receives a VulnerabilityReport it may do one of two things:

- Extract tags from the provided VulnerabilityReport and utilize the EnrichmentGetter
interface to retrieve local Enrichments.
- Send the VulnerabilityReport to a remote api for further processing.

These two options are canonically referred to as "local" and "remote" Enrichers,
respectively.

The returned value is a client-facing Mime key and a slice of Enrichment data in
serialized JSON form.

#### MIME type usage

MIME types associated with Enrichments play an important role.

Clair views all Enrichments as schemaless but requires a MIME type to be associated
with each Enrichment associated with a Vulnerability or Manifest

All Enrichments **must** be associated with a MIME type.

Clair provides its own "container" MIME type convention.

In the common case Enrichers returning Vulnerability Enrichments will map these
Enrichments to Vulnerabilities in the Vulnerability Report.

To inform the client a well-defined datatype is being associated with a
Vulnerability inside the Vulnerability Report, Clair defines the following MIME 
type convention:

The MIME type of `message/vnd.clair.map.vulnerability` declares that each associated
Enrichment is wrapped in a map.

This map is keyed by the vulnerability ID it maps to.

For example:

```json
{
  "18": { ...nvd enrichment data... }
}
```

In the above example the NVD Enrichment data is wrapped in a map which associates
Vulnerability.ID == 18 with that NVD Enrichment data.

Furthermore, the Enricher can augment the MIME type with a "type" **OR** "schema"
key.

The following expresses the rules around the two aforementioned MIME type keys:

If the Enricher can identify a web hosted schema for the Enrichment being wrapped
in a map it **must** add the "schema" key to the container MIME type.

The "schema" key should have a hyperlink to a jsonchema or similar value defining
the structure of the data.

In absense of a "schema" key, if the Enricher provides data with a consistent
schema it **must** document this schema in Clair's upstream documentation, give
it a unique type name, and add the "type" key to the container MIME type.

If the Enricher determines it is handling a completely schema agonstic Enrichment
type it **must** not use the `message/vnd.clair.map.vulnerability` MIME type and
default to the base MIME type provided by the EnrichmentRecord.

For example, an Enricher who is returning NVD data keyed by Vulnerability ID will
return its data with the following MIME type:

```text
message/vnd.clair.map.vulnerability; enricher=com.rhel.nvd schema=https://csrc.nist.gov/schema/nvd/feed/1.1-Beta/nvd_cve_feed_json_1.1_beta.schema
```

As another example, an Enricher who has a well defined schema but this schema is
not hosted on the internet will define a data type in Clair's upstream documentation.

```golang
type MyEnrichmentData struct {
  Data string
}
```

And then return their Enrichment data with the following MIME type:

```text
message/vnd.clair.map.vulnerability; type=MyEnrichmentData
```

### EnrichmentGetter

A new interface will be created in libvuln's driver package for obtaining EnrichmentRecords.

```golang
// EnrichmentGetter is a handle to obtain Enrichment(s) given a tag.
//
// This interface must be scoped down to only retrieve EnrichmentRecord(s)
// associated with a single MIME type.
type EnrichmentGetter interface {
	GetEnrichment(context.Context, []string) ([]EnrichmentRecord, error)
}
```

The EnrichmentGetter allows implemented Enrichers to retrieve Enrichment(s)
without providing total access to all Enrichment data.

### Vulnstore

Two new interfaces will be added to the `vulnstore` package.


```golang
// Enricher is an interface exporting the necessary methods
// for storing and querying Enrichments.
type EnrichmentUpdater interface {
	// UpdateEnrichments creates a new EnrichmentUpdateOperation, inserts the provided
	// EnrichmentRecord(s), and ensures enrichments from previous updates are not
	// queries by clients.
	UpdateEnrichments(ctx context.Context, mime string, fingerprint driver.Fingerprint, enrichments []claircore.EnrichmentRecord)
}
```

The EnrichmentUpdater interface will be embedded into the Updater interface as
methods on the Updater interface will pertain to Enrichment data as well.

```golang
type Enrichment interface {
	GetEnrichment(ctx context.Context, mime string, tags []string) ([]driver.EnrichmentRecord, error)
}
```

The Enrichment interface will stand alone and provide a method for obtaining 
EnrichmenRecord(s) given a mime string and a set of tags.

### Enriching the VulnerabilityReport

The VulnerabilityReport will grow a "Enrichments" field.

```golang
// VulnerabilityReport provides a report of packages and their
// associated vulnerabilities.
type VulnerabilityReport struct {
	// the manifest hash this vulnerability report is describing
	Hash Digest `json:"manifest_hash"`
	// all discovered packages in this manifest keyed by package id
	Packages map[string]*Package `json:"packages"`
	// all discovered distributions in this manifest keyed by distribution id
	Distributions map[string]*Distribution `json:"distributions"`
	// all discovered repositories in this manifest keyed by repository id
	Repositories map[string]*Repository `json:"repository"`
	// a list of environment details a package was discovered in keyed by package id
	Environments map[string][]*Environment `json:"environments"`
	// all discovered vulnerabilities affecting this manifest
	Vulnerabilities map[string]*Vulnerability `json:"vulnerabilities"`
	// a lookup table associating package ids with 1 or more vulnerability ids. keyed by package id
	PackageVulnerabilities map[string][]string `json:"package_vulnerabilities"`
    // a map of enrichments keyed by a well defined MIME type.
    Enrichments map[string][]json.RawMessage
}
```

The Enrichment field will contain keys with MIME types defined in the
"MIME type usage" section and anarray of json messsages.

Clair does not attempt to understand the json schemas and the MIME type will provide
the necessary hints for a client to understand the contents.
