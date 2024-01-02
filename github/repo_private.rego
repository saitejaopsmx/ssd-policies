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

private_repo = response.body.private

deny[msg]{
  private_repo = false
  msg := sprintf("Git repo is a public repo %v", [input.metadata.github_repo])
}
