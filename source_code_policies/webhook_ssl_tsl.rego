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
deny[msg]{

response.body[_].insecure_ssl != 0
msg := ("Webhook is not protected with SSL")

}
