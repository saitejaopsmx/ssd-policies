package opsmx

default allow = false

request_components = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo,"dependency-graph/sbom"]
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

#sbom_check = response.body.status_code

deny[msg] {
    response.status_code != 200
    msg := sprintf("Failed to retrieve SBOM from GitHub repository %v", [input.metadata.github_repo])
}
