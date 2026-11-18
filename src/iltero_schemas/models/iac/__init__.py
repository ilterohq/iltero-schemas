"""Models of changes made with an infrastructure-as-code (IaC) tool: the tools a record may name (``tool_names``),
the deployment (``deployment``) and the marker it writes where its sources lost a fact (``markers``), the drift
check (``drift_check``), the resource identities document (``resource_identities``), each tool's own shapes
(``tools``), the scanner check mapping (``scanner_check_mapping``), the files a stage kept for its scanner results
(``kept_files``) and the check of each scanner evaluation against them (``scanner_results``)."""
