package opsmx

default allow = false

request_components = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo,"branches",input.metadata.branch, "protection"]
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

delete_branch = response.body.allow_deletions.enabled

deny[msg]{
  delete_branch = false
  msg := sprintf("Github repo %v of branch %v is having policy and branch cannot be deleted", [input.metadata.github_repo,input.metadata.branch])
}
