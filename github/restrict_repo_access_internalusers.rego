package opsmx

default allow = false

request_components = [input.metadata.rest_url,"orgs", input.metadata.github_org, "outside_collaborators"]
collaboraters_url = concat("/",request_components)

repo_components = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo, "collaborators?affiliation=direct"]
repo_url = concat("/",repo_components)

orgtoken = input.metadata.orggithub_access_token

token = input.metadata.github_access_token

collaboraters = {
    "method": "GET",
    "url": collaboraters_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [orgtoken]),
    },
}

request = {
    "method": "GET",
    "url": repo_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}

collaboraters_response = http.send(collaboraters)

response = http.send(request)

response_result = response.body

outside_collaboraters_result = collaboraters_response.body

outside_users = {outsideuser |
    some i
    outsideuser = outside_collaboraters_result[i];
    outsideuser.type == "User"
}

repo_users = {repouser |
    some i
    repouser = response_result[i];
    repouser.type == "User"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
    outsideuser = outside_users[_]
    repouser = repo_users[_]
    outsideuser.login == repouser.login
    msg = sprintf("Git repo %s is accessed by outside collaborator user %v", [input.metadata.github_repo,outsideuser.login])
    sugg := sprintf("Adhere to the company policy and revoke access of non-organization members for %s repository",[outsideuser.login])
    error := ""
}
