package opsmx

default allow = false

policy_name := input.conditions[0].condition_name
condition_value := input.conditions[0].condition_value
min_threshold := split(condition_value, "-")[0]
max_threshold := split(condition_value, "-")[1]
#min_threshold := to_number(min_threshold_str)
#max_threshold := to_number(max_threshold_str)

allScores = score {
  result := input.metadata.results[_]
  result.name == policy_name
  score = result.score
}

documentationurls = url {
  result := input.metadata.results[_]
  result.name == policy_name
  url = result.documentation.url
}

documentationmsg = msgs {
  result := input.metadata.results[_]
  result.name == policy_name
  msgs = result.documentation.short
}

#allow {
#  allScores < min_threshold
#}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  allScores > min_threshold
  msg := sprintf("%v score for the repo %s is %v which is greater than than %v out of %v", [policy_name,input.metadata.name,allScores,min_threshold,max_threshold])
  sugg = sprintf("%v Refer to the OpenSSF documentation %v", [documentationmsg,documentationurls])
  error = ""
}

#deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
#  allScores > max_threshold
#  msg := sprintf("%v score for the repo %s is %v which is less than %v out of %v", [policy_name,input.metadata.name,allScores,min_threshold,max_threshold])
#  sugg = sprintf("%v Refer to the OpenSSF documentation %v", [documentationmsg,documentationurls])
#  error = ""
#}
