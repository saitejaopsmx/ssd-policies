package opsmx

default allow = false

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

repo_access_control = response.body.visibility

deny[msg]{
  repo_access_control = "public"
  msg := sprintf("Safeguard sensitive information by making %v Github repo private", [input.metadata.github_repo])
}
