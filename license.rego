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

license_check = response.body.license

deny[msg]{
  license_check = null
  msg := sprintf("GitHub License not found for the %v repo", [input.metadata.github_repo])
}
