package opsmx

default allow = false

request_components = [input.metadata.rest_url, "orgs", input.metadata.github_org, "members?role=admin"]
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

users = {user |
    some i
    user = result[i];
    user.type == "User"
}

org_users = {"bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"}

deny[msg] {
    user = users[_]
    user.login == org_users[user.login]
    msg = sprintf("GitHub Organisation is accessed by '%v' which is not allowed.", [user.login])
}
