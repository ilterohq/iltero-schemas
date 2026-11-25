"""Models of changes made with an infrastructure-as-code (IaC) tool: the tools a record may name (``tool_names``),
the deployment (``deployment``) and the marker it writes where its sources lost a fact (``markers``), the drift
check (``drift_check``), the resource identities document (``resource_identities``), each tool's own shapes
(``tools``), the scanner check mapping (``scanner_check_mapping``), the limits of the documents a scanning stage
sends (``sent_document_limits``) and the check of each scanner evaluation against the files its stages kept
(``scanner_results``)."""
