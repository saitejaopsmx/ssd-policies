package opsmx

default allow = false
default private_repo = ""

request_components = [input.metadata.rest_url,"orgs", input.metadata.github_org]
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

mfa_enabled = response.body.two_factor_requirement_enabled

deny[msg]{
  mfa_enabled = false
  msg := sprintf("Github repository doest have the mfa enabled", [input.metadata.github_org])
}
