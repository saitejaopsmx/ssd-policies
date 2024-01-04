package opsmx

request_url_p1 = concat("/",[input.metadata.sonarqube_address,"api/qualitygates/project_status?projectKey"])
request_url = concat("=", [request_url_p1, input.metadata.sonarqube_projectKey])


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
  msg := sprintf("Error: 404 Not Found. Quality Gate not found for project %s.", [input.metadata.sonarqube_projectKey])
}

deny[msg]{
  response.status_code == 403
  msg := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read Quality Gate status project %s.", [input.metadata.sonarqube_projectKey])
}

deny[msg]{
  response.body.projectStatus.status == "ERROR"
  msg := sprintf("SonarQube Quality Gate Status Check has failed for project %s. Prioritize and address the identified issues promptly to meet the defined quality standards and ensure software reliability.", [input.metadata.sonarqube_projectKey])
}
