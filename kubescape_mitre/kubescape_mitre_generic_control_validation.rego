package opsmx
import future.keywords.in

policy_name = input.conditions[0].condition_name
control_id = split(policy_name, " -")[0]

deny[msg] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",\n",failed_resources)])
}
