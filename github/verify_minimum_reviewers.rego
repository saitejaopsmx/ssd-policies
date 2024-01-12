package opsmx
import future.keywords.in

default allow = false

required_min_reviewers = {input.conditions[i].condition_value|input.conditions[i].condition_name == "Minimum Reviewers Policy"}

request_components = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository,"branches",input.metadata.branch, "protection"]
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
raw_body = response.raw_body
parsed_body = json.unmarshal(raw_body)
reviewers = response.body.required_pull_request_reviews.required_approving_review_count

allow {
  response.status_code = 200
}
deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code == 401
  msg := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
  error := "401 Unauthorized."
  sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := "Mentioned branch for Repository not found while trying to fetch repository branch protection policy configuration."
  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
  error := "Repo name or Organisation is incorrect."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 500
  msg := "Internal Server Error."
  sugg := ""
  error := "GitHub is not reachable."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 404, 500, 200, 301, 302]
  not response.status_code in codes
  msg := "Unable to fetch repository branch protection policy configuration."
  error := sprintf("Error %v:%v receieved from Github upon trying to fetch repository branch protection policy configuration.", [response.status_code, response.body.message])
  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  reviewers == 0
  msg := sprintf("The branch protection policy that mandates a pull request before merging has been deactivated for the %s branch of the %v on GitHub", [input.metadata.branch,input.metadata.repository])
  sugg := sprintf("Adhere to the company policy by establishing the correct minimum reviewers for %s Github repo", [input.metadata.repository])
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  reviewers < required_min_reviewers
  msg := sprintf("The branch protection policy that mandates a pull request before merging has mandatory reviewers count less than required for the %s branch of the %v on GitHub", [input.metadata.branch,input.metadata.repository])
  sugg := sprintf("Adhere to the company policy by establishing the correct minimum reviewers for %s Github repo", [input.metadata.repository])
  error := ""
}
