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

status = response.status

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

admin_percentage = admin_users / total_users * 100

allow {
  response.status_code = 200
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 404
  msg := ""
  sugg := "Please provide the appropriate repo name"
  error := "Repo name or Organisation is incorrect"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 401
  msg := ""
  sugg := "Please provide the Appropriate Git Token for the User"
  error := sprintf("%s %v", [message,status])
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 500
  msg := "Internal Server Error"
  sugg := ""
  error := "GitHub is not reachable"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  admin_percentage > input.conditions[0].condition_value
  msg := sprintf("More than 5 percentage of total collaborators of %v github repository have admin access", [input.metadata.github_repo])
  sugg := sprintf("Adhere to the company policy and revoke admin access to some users of the repo %v", [input.metadata.github_repo])
  error := ""
}
