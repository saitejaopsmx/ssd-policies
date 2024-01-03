package opsmx

request = {
    "method": "POST",
    "url": "http://localhost:8100/api/v1/artifactSign",
    "body": {
        "image": input.metadata.image,
        "imageTag": input.metadata.imageTag,
        "registryUser": input.metadata.registryUser,
        "registryPass": input.metadata.registryPass
    }
}

response = http.send(request)

deny[msg] {
    response.body.code = 500
    msg = sprintf("Artifact is not signed. Response code: %v", [response.body.code])
}

