package opsmx

default allow = false

policy_name = "Open SSF Aggregate Policy"
condition_value := input.conditions[0].condition_value
min_threshold := split(condition_value, "-")[0]
max_threshold := split(condition_value, "-")[1]
score := input.metadata.aggregate_score

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  score > min_threshold
  msg := sprintf("Aggregate score for repo %v is %v, which is less than %v out %v", [input.metadata.name, score, min_threshold, max_threshold])
  sugg := ""
  error := ""
}

#deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
#  score <= max_threshold
#  msg := sprintf("%v scan failed with score:%v on cluster %v.", [input.metadata.scan_type, score, input.metadata.account_name])
#  sugg := ""
#  error := ""
#}
