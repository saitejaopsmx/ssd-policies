package opsmx

default allow = false
default auto_merge_config = ""

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

auto_merge_config = response.body.allow_auto_merge

deny["Auto Merge Config Not Found, indicates Branch Protection Policy is not set"]{
  auto_merge_config == ""
}

deny[msg]{
  auto_merge_config != input.conditions[0].condition_value
  msg := sprintf("Auto Merge is allowed in repo %v", [input.metadata.github_repo])
}
