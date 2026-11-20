# Roadmap

## Phase 1: records and seals
- `init`, `doc add`, `check`, `status`, `rotate`, `seal`, `verify`.
- Manual event entry from `templates/`.
- Local HMAC authority for tests and examples; RFC 3161 authorities for
  real use.
- `periods/index.yaml`, manifests, `state.yaml` with FIFO lots.

## Phase 2: hand-over and housekeeping
- `export csv` in the consultant's two-table layout; `export euer`;
  `export fifo`.
- `export gobd`: CSV plus `index.xml` validated against the GDPdU DTD.
- `checkpoint`, `archive`, `expire`, `gc`, `checkout`, `diff`, `log`.
- `seal collect`, `seal attach`, abandoned-authority markers.
- OpenTimestamps as optional second authority.

## Phase 3: e-invoices
- `invoice render ID`: from an `invoice` event and the counterparty's
  master data, produce the human PDF and the structured XML (XRechnung, or
  ZUGFeRD as PDF/A-3 with the XML embedded).
- Validate locally before storing: schema plus the German business rules
  (Schematron). Candidates: Mustangproject CLI for generation and validation,
  or the KoSIT validator for validation only. Both need a Java runtime, which
  becomes an optional dependency of this phase only. Pure-Python libraries
  (factur-x, drafthorse) can generate but validate against the schema only.
- Store PDF, XML and the text sidecar side by side under `docs/invoices/`, each
  registered as a `document` event and all referenced from the `invoice` event.
  The XML is the legal original for a recipient under the e-invoice obligation
  and must be kept byte-identical.
- Receiving side: `doc add` recognises an incoming XRechnung or ZUGFeRD file,
  validates it, extracts its text into the sidecar.

## Later
- Textual terminal UI over the same library functions.
- Rate fetching (`rate SOURCE DATE`) with evidence files saved automatically.
- `verify --backup PATH` and `backup --check`.
