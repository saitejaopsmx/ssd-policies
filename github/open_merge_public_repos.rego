package opsmx

default allow = false

repo_search = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo]
repo_searchurl = concat("/",repo_search)

branch_search = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo,"branches",input.metadata.default_branch]
branch_searchurl = concat("/",branch_search)

protect_components = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo,"branches",input.metadata.default_branch,"protection"]
protect_url = concat("/",protect_components)

token = input.metadata.github_access_token

repo_search_request = {
    "method": "GET",
    "url": repo_searchurl,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}

branch_search_request = {
    "method": "GET",
    "url": branch_searchurl,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}

protect_search_request = {
    "method": "GET",
    "url": protect_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}

response = http.send(repo_search_request)

branch_response = http.send(branch_search_request)

branch_protect = http.send(protect_search_request)

branch_check = response.body.default_branch

AllowAutoMerge = response.body.allow_auto_merge

delete_branch_on_merge = response.body.delete_branch_on_merge

branch_protected = branch_response.body.protected

RequiredReviewers = branch_protect.body.required_pull_request_reviews.required_approving_review_count

AllowForcePushes = branch_protect.body.allow_force_pushes.enabled

#AllowDeletions = branch_response.body.allow_deletions.enabled

RequiredSignatures = branch_protect.body.required_signatures.enabled

EnforceAdmins = branch_protect.body.enforce_admins.enabled

RequiredStatusCheck = branch_protect.body.required_status_checks.strict


deny[msg]{
  branch_check = " "
  msg := sprintf("Github does not have any branch", [input.metadata.github_repo])
}

deny[msg]{
  AllowAutoMerge = true
  msg := sprintf("Github repo %s has allow automatic merge enabled, Please disable it", [input.metadata.github_repo])
}

deny[msg]{
  delete_branch_on_merge = true
  msg := sprintf("Deleting the branch after merge is enabled for the repo %s, Please disable it", [input.metadata.github_repo])
}
	
deny[msg]{
  branch_protected = false
  msg := sprintf("Github repo %v and branch %v is not protected", [input.metadata.github_repo, input.metadata.default_branch])
}

deny[msg]{
  RequiredReviewers = 0
  msg := sprintf("Atleast 1 reviewer is required for merging the repo %s", [input.metadata.github_repo])
}

deny[msg]{
  AllowForcePushes = true
  msg := sprintf("Force push is enabled for the repo %s", [input.metadata.github_repo])
}

#deny[msg]{
#  AllowDeletions = true
#  msg := sprintf("Deleting the branch after merge is enabled for the repo %s, Please disable it", [input.metadata.github_repo])
#}

deny[msg]{
  RequiredSignatures = false
  msg := sprintf("Required Signatures is disabled for the repo %s, Please enable it", [input.metadata.github_repo])
}

deny[msg]{
  EnforceAdmins = true
  msg := sprintf("Enforce Admins is enabled for the Github repo %s, Please disable it", [input.metadata.github_repo])
}

deny[msg]{
  RequiredStatusCheck = false
  msg := sprintf("The branch protection policy that requires status check is disabled for the repo %s, Please enable it", [input.metadata.github_repo])
}
