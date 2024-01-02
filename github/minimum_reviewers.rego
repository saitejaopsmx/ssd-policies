package opsmx

default allow = false

request_components = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo,"branches",input.metadata.default_branch, "protection"]
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

reviewers = response.body.required_pull_request_reviews.required_approving_review_count

deny[msg]{
  reviewers = 0 
  msg := sprintf("There should be atleast 1 reviewer in %s repo for Merging the code", [input.metadata.github_repo])
}
