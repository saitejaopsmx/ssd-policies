package opsmx

input_str := input.conditions[0].condition_value
threshold = to_number(input_str)

deny[msg] {
  score := input.metadata.compliance_score
  score <= threshold
  msg := sprintf("%v scan failed with score:%v on cluster %v.", [input.metadata.scan_type, score, input.metadata.account_name])
}
