package opsmx

default allow = false
code_url = input.metadata.repository
parts := split(code_url, "/")
github_org = parts[3]
github_repo = parts[4]

request_components = ["https://api.github.com","repos", github_org, github_repo,"dependency-graph","sbom"]
request_url = concat("/",request_components)
token = input.metadata.github_access_token
request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}

response = http.send(request)

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 404
  msg := ""
  sugg := "Please provide the appropriate repo name"
  error := "Repo name or Organisation is incorrect"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 401
  msg := ""
  sugg := "Please provide the Appropriate Git Token for the User"
  error := sprintf("%s %v", [message,status])
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 500
  msg := "Internal Server Error"
  sugg := ""
  error := "GitHub is not reachable"
}

packages_without_version := [response.sbom.packages[i].name | response.sbom.packages[i].versionInfo == ""]
results = [packages_without_version[j] | not startswith(packages_without_version[j], "actions")]
deny["msg"]{
  count(results) > 0
  msg := sprintf("The GitHub repository '%v' exhibits packages with inadequate versioning.", [input.metadata.repository])
}
