package opsmx

default allow = false

request_components = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo, "collaborators"]
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

raw_body = response.raw_body

parsed_body = json.unmarshal(raw_body)

message = parsed_body.message

responsesplit = response.body

admins = {user |
    some i
    user = responsesplit[i];
    user.role_name == "admin"
}

admin_users = count(admins)

total = {user |
    some i
    user = responsesplit[i];
    user.type == "User"
}

total_users = count(total)

admin_percentage = admin_users / total_users

allow {
  response.status_code = 200
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 404
  msg := "Repo name or Organisation is incorrect"
  sugg := "Please provide the appropriate details"
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 401
  msg := sprintf("Authentication failed for the repo with the error %s", [message])
  sugg := "Incorrect git credentails of the user"
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 500
  msg := "Internal Server Error"
  sugg := "GitHub is not reachable"
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  admin_percentage > 0.05
  msg := sprintf("More than 5 percentage of total collaborators of %v github repository have admin access", [input.metadata.github_repo])
  sugg := "Please remove some of the users from the collaborators"
  error := ""
}
