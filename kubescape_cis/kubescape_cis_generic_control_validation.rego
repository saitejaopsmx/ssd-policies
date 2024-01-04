package opsmx
import future.keywords.in

policy_name = input.conditions[0].condition_name

deny[msg] {
  input.metadata.results[i].control_title == policy_name
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy_name, input.metadata.account_name, concat(",\n",failed_resources)])
}
