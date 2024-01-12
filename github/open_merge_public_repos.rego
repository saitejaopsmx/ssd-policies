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

AllowDeletions = branch_response.body.allow_deletions.enabled

RequiredSignatures = branch_protect.body.required_signatures.enabled

EnforceAdmins = branch_protect.body.enforce_admins.enabled

RequiredStatusCheck = branch_protect.body.required_status_checks.strict


deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  branch_check = " "
  msg := "Github does not have any branch"
  sugg := "Please create a branch"
  error := ""
} 

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  AllowAutoMerge = true
  msg := sprintf("The Auto Merge is enabled for the %s owner %s repo", [input.metadata.github_repo, input.metadata.default_branch])
  sugg := "Please disable the Auto Merge"
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  delete_branch_on_merge = true
  msg := "The branch protection policy that allows branch deletion is enabled."
  sugg := sprintf("Please disable the branch deletion of branch %s of repo %s", [input.metadata.default_branch,input.metadata.github_repo])
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  branch_protected = false
  msg := sprintf("Github repo %v and branch %v is not protected", [input.metadata.github_repo, input.metadata.default_branch])
  sugg := sprintf("Make sure branch %v of %v repo has some branch policies", [input.metadata.github_repo,input.metadata.default_branch])
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  RequiredReviewers = 0
  msg := "The branch protection policy that mandates the minimum review for branch protection has been deactivated."
  sugg := sprintf("Activate branch protection: pull request and minimum 1 approval before merging for branch %s of %s repo",[input.metadata.default_branch,input.metadata.github_repo])
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  AllowForcePushes = true
  msg := "The branch protection policy that allows force pushes is enabled."
  sugg := sprintf("Please disable force push of branch %v of repo %v", [input.metadata.default_branch,input.metadata.github_repo])
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  AllowDeletions = true
  msg := "The branch protection policy that allows branch deletion is enabled."
  sugg := sprintf("Please disable the branch deletion of branch %v of repo %v",[input.metadata.default_branch,input.metadata.github_repo])
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  RequiredSignatures = true
  msg := "The branch protection policy that requires signature is disabled."
  sugg := sprintf("Please activate the mandatory GitHub signature policy for branch %v signatures of %v repo",[input.metadata.default_branch,input.metadata.github_repo])
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  EnforceAdmins = true
  msg := sprintf("The branch protection policy that enforces status checks for repository administrators is disabled", [input.metadata.github_repo])
  sugg := sprintf("Please activate the branch protection policy, don't by pass status checks for repository administrators of branch %s of %s repo",[input.metadata.default_branch,input.metadata.github_repo])
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  RequiredStatusCheck = true
  msg := sprintf("The branch protection policy that requires status check is disabled for the repo %s", [input.metadata.github_repo])
  sugg := sprintf("Please activate the branch protection policy, requiring a need to be up-to-date with the base branch before merging for branch %s of %s repo",[input.metadata.default_branch,input.metadata.github_repo])
  error := ""
}
