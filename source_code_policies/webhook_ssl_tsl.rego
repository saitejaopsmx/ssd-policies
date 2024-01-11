package opsmx

default allow = false
split_url{
  code_url = input.metadata.repository
  parts := split(code_url, "/")
  github_org = parts[3]
  github_repo = parts[4]
}
request_components = [input.metadata.rest_url,"repos", github_org, github_repo, "hooks"]
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

deny[msg]{

response.body[_].insecure_ssl != 0
msg := ("Webhook is not protected with SSL")

}
