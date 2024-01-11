package opsmx

default allow = false
default private_repo = ""

request_components = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo]
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

raw_body = response.raw_body

parsed_body = json.unmarshal(raw_body)

private_repo = response.body.private

allow {
  response.status_code = 200
}

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
  error := sprintf("%s %v", [parsed_body.message,response.status])
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 500
  msg := "Internal Server Error"
  sugg := ""
  error := "GitHub is not reachable"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  private_repo = false
  msg := sprintf("Git repo is a public repo %v", [input.metadata.github_repo])
  sugg := "Please change the repo to private"
  error := ""
}
