package opsmx

severity = "low"

request_components = [input.metadata.toolchain_addr,"api", "v1", "scanResult"]
request_url = concat("/",request_components)
filename_components = ["fileName=findings", input.metadata.github_org, input.metadata.github_repo, severity, input.metadata.build_id, "semgrep.json"]
filename = concat("_", filename_components)

complete_url = concat("?", [request_url, filename])

request = {
    "method": "GET",
    "url": complete_url
}

response = http.send(request)

findings_count = response.body.totalFindings

deny[msg]{
  findings_count > 0
  msg := sprintf("The https://www.github.com/%v/%v repository contains %v findings of %v severity.", [input.metadata.github_org, input.metadata.github_repo, findings_count, severity])
}
