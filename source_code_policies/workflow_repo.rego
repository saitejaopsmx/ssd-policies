package opsmx

default allow = false
default auto_merge_config = ""
split_url{
  code_url = input.metadata.repository
  parts := split(code_url, "/")
  github_org = parts[3]
  github_repo = parts[4]
}
request_components = [input.metadata.rest_url,"repos", github_org, github_repo, "actions", "permissions", "workflow"]
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
  response.body.default_workflow_permissions != "read"
  msg := ("Default workflow permissions for repo is not set to read")
}
