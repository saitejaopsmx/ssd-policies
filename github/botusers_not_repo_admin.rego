package opsmx

default allow = false

request_components = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo, "collaborators?affiliation=direct"]
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

admins = {user |
    some i
    user = result[i];
    user.role_name == "admin"
}

bot_users = {"bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"}

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
  error := sprintf("%s %v", [parsed_body.message,response.status])
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 500
  msg := "Internal Server Error"
  sugg := ""
  error := "GitHub is not reachable"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  user = admins[_]
  user.login == bot_users[user.login]
  msg = sprintf("Git repo is owned by bot user %s", [user.login])
  sugg := sprintf("Adhere to the company policy and revoke access of bot user for %s Organization", [user.login])
  error := ""
}
