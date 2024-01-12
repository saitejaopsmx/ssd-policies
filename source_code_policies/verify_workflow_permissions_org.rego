package opsmx
import future.keywords.in

default allow = false

request_components = [input.metadata.ssd_secret.github.rest_api_url,"orgs", input.metadata.owner, "actions", "permissions", "workflow"]
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
  msg := "Unauthorized to check Organisation Workflow Permissions."
  error := "401 Unauthorized."
  sugg := "Kindly check the access token. It must have enough permissions to get organisation workflow permissions."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := "Mentioned Organisation not found while trying to fetch organisation workflow permissions."
  sugg := "Kindly check if the organisation provided is correct."
  error := "Organisation name is incorrect."
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
  msg := "Unable to fetch organisation workflow permissions."
  error := sprintf("Error %v:%v receieved from Github upon trying to fetch organisation workflow permissions.", [response.status_code, response.body.message])
  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.body.default_workflow_permissions != "read"
  msg := sprintf("Default workflow permissions for Organisation %v is not set to read.", [input.metadata.owner])
  sugg := sprintf("Adhere to the company policy by enforcing default_workflow_permissions of Organisation %s to read only.", [input.metadata.owner])
  error := ""
}
