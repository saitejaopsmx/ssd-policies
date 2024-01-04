package opsmx

request_url = sprintf("%s/api/measures/component?metricKeys=%s&component=%s", [input.metadata.sonarqube_address, input.conditions[0].condition_name, input.metadata.sonarqube_projectKey])

request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [input.metadata.sonarqube_token]),
    },
}

response = http.send(request)

deny[msg]{
  response.status_code == 404
  msg := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
}

deny[msg]{
  response.status_code == 403
  msg := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
}

deny[msg]{
  response.body.component.measures[0].period.value == input.conditions[0].condition_value
  msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [input.conditions[0].condition_name, input.conditions[0].condition_value, input.metadata.sonarqube_projectKey])
}
