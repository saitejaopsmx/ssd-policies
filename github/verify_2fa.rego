package opsmx
import future.keywords.in

default allow = false

request_components = [input.metadata.ssd_secret.github.rest_api_url,"orgs", input.metadata.owner]
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
mfa_enabled = response.body.two_factor_requirement_enabled

allow {
  response.status_code = 200
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code == 401
  msg := "Unauthorized to check organisation configuration due to Bad Credentials."
  error := "401 Unauthorized."
  sugg := "Kindly check the access token. It must have enough permissions to get organisation configurations."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := "Mentioned Organisation not found while trying to fetch org configuration."
  sugg := "Kindly check if the organisation provided is correct and the access token has rights to read organisation configuration."
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
  msg := "Unable to fetch organisation configuration."
  error := sprintf("Error %v:%v receieved from Github upon trying to fetch organisation configuration.", [response.status_code, response.body.message])
  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  mfa_enabled == null
  msg := sprintf("Github Organisation %v doesn't have the mfa enabled.", [input.metadata.owner])
  sugg := sprintf("Adhere to the company policy by enabling 2FA for %s.",[input.metadata.owner])
  error := ""
}
