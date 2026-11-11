# Upload a PDF by file reference

PSA Command 1.4.3 and the standalone Node MCP expose `psa_upload_pdf_file`. The existing `psa_upload_pdf` tool remains available for small inline payloads. No website changes, database migration, paid service or new Google credential is needed.

Give the AI an explicitly selected, absolute local PDF path on the computer running its MCP bridge. The model sends only that short reference, not base64. The bridge reads the file and transfers it to the existing authenticated PSA attachment catalog endpoint; the returned asset ID can be used by the existing template tools. Maximum 10 MiB, matching catalog uploads. Files are never executed, and this operation does not send mail or approve a campaign.

First call: `psa_upload_pdf_file(file_path=<absolute PDF path>)`. The preview returns filename, bytes and expected_sha256. After the upload preview is approved, repeat with the same path, `confirm=true` and that expected_sha256. A changed file requires a new preview. The bridge checks admin/library management permission before accessing the source. It rejects relative paths, URLs, network/device paths, linked directories, nonregular files, invalid PDF headers and oversize files. The API independently enforces authorization and file limits again.

The path is local to the MCP process, not Render and not an arbitrary remote AI provider. When using a remote AI service, configure its local MCP bridge on the computer holding the PDF. Keep paths and catalog output free of credentials; never supply secret files or scan for files that the user did not choose.

For Google Drive: download or sync the PDF locally first, then use its regular local path. A private Drive file ID alone is not supported by the present tab contract; this tool does not extract Google tokens or use public-link workarounds. Direct authenticated Drive-ID import remains a separate integration.

After installing PSA Command 1.4.3, Check the PSA Command MCP connection and review/accept the new tool in Tool Store > Tools. Select the integration in the chat. Changed installed tab source requires normal source review and may require restarting the tab/app to reload Python. Existing PSA account keys and catalog PDFs remain unchanged.

Tests use synthetic PDFs including a 2.9 MB flyer and fake/local API transports. No real flyer, email or campaign is changed by tests.
