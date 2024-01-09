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

result = response.body

alllogins = {user |
    some i
    user = result[i];
    user.permissions.admin == true
    user.permissions.maintain == true
}

bot_users = {"bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"}

deny[msg] {
    user = alllogins[_]
    user.login == bot_users[user.login]
    msg = sprintf("Github users cannot merge the code '%v'", [user.login])
}
