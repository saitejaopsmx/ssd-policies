package opsmx
import future.keywords.in

default allow = false

request_components = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository, "branches", input.metadata.branch, "protection", "required_signatures"]
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

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code == 401
  msg := "Unauthorized to check repository branch configuration due to Bad Credentials."
  error := "401 Unauthorized."
  sugg := "Kindly check the access token. It must have enough permissions to get repository branch configurations."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := "Mentioned branch for Repository not found while trying to fetch repository branch configuration."
  sugg := "Kindly check if the repository and branch provided is correct and the access token has rights to read repository branch protection policy configuration."
  error := "Repo name, Branch name or Organisation name is incorrect."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 500
  msg := "Internal Server Error."
  sugg := ""
  error := "GitHub is not reachable."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 404, 500, 200, 302]
  not response.status_code in codes
  msg := "Unable to fetch repository branch configuration."
  error := sprintf("Error %v:%v receieved from Github upon trying to fetch repository branch configuration.", [response.status_code, response.body.message])
  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code in [200, 302]
  response.body.enabled != true
  msg := sprintf("Branch %v of Github Repository %v/%v does not have signed commits mandatory.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
  error := ""
  sugg := sprintf("Adhere to the company policy by enforcing all commits to be signed for %v/%v Github repo", [input.metadata.owner, input.metadata.repository])
}
