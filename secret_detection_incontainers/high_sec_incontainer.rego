package opsmx
default allow = false
file_components = [input.metadata.repo, input.metadata.id, "imageScanResult.json"]
filename = concat("_",file_components)
request_components = [input.metadata.toolchain_url, filename ]
request_url = concat("=",request_components)
request = {
    "method": "GET",
    "url": request_url
}

response = http.send(request)
results := [input.Results[i].Secrets[j].Title | input.Results[i].Secrets[j].Severity == "HIGH"]
counter = count(results)
deny[msg]{

  counter != 0
  msg := sprintf("%v is detected in container %v",[results, input.metadata.repo])

}
