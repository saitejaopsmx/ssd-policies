package opsmx

default allow = false

request_components = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo,"branches",input.metadata.default_branch]
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

branch_protected = response.body.protected

deny[msg]{
  branch_protected = false
  msg := sprintf("Github repo %v and branch %v is not protected ", [input.metadata.github_repo, input.metadata.default_branch])
}
