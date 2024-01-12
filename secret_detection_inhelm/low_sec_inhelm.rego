package opsmx
default allow = false
file_components = [input.metadata.repo, input.metadata.id, "helmScanResult.json"]
filename = concat("_",file_components)
request_components = [input.metadata.toolchain_url, filename ]
request_url = concat("=",request_components)
request = {
    "method": "GET",
    "url": request_url
}

response = http.send(request)

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 500
  msg := "helmScanResult.json file is not available in tool-chain service or file name is wrong"
  sugg := ""
  error := "Internal Server Error"
}

results := [response.Results[i].Secrets[j].Title | response.Results[i].Secrets[j].Severity == "LOW"]
counter = count(results)
deny[msg]{

  counter != 0
  msg := sprintf("%v is detected in container %v",[results)

}
