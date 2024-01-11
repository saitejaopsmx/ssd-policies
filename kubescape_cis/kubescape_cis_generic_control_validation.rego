package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  sugg = [input.metadata.suggestions[i].suggestion | lower(input.metadata.suggestions[i].policy_name) == lower(policy)]
  suggestion := concat(",\n", [sugg[0], "References: ", input.metadata.references])
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",\n",failed_resources)])
  error := ""
}
