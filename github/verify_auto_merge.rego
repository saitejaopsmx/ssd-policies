package opsmx
import future.keywords.in

default allow = false
default auto_merge_config = ""

request_components = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository]
request_url = concat("/",request_components)

token = input.metadata.ssd_secret.github.token

request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}

response = http.send(request)

auto_merge_config = response.body.allow_auto_merge
status_code = response.status_code

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code == 401
  msg := "Unauthorized to check the Branch Protection Policy"
  error := "401 Unauthorized"
  sugg := "Kindly check the access token. It must have enough permissions to read the branch protection policy for repository."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 200, 301, 302]
  not response.status_code in codes
  msg = "Unable to fetch Branch Protection Policy"
  error = sprintf("Error %v:%v receieved from Github upon trying to fetch Branch Protection Policy.", [status_code, response.body.message])
  sugg = "Kindly check Github API is reachable and the provided access token has required permissions."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  status_code in [200, 301, 302]
  auto_merge_config == ""
  msg = "Auto Merge Config Not Found, indicates Branch Protection Policy is not set"
  error = ""
  sugg = "Kindly configure Branch Protection Policy for source code repository and make sure to restrict auto merge."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  status_code in [200, 301, 302]
  auto_merge_config != input.conditions[0].condition_value
  msg = sprintf("Auto Merge is allowes in repo %v", [input.metadata.repository])
  error = ""
  sugg = "Kindly restrict auto merge in Branch Protection Policy applied to repository."  
}
