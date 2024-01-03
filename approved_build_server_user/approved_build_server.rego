package opsmx

default allow = false

build_url = input.metadata.build_url
deny[msg]{
    parts := split(build_url, "/")
    provided_host = parts[2] 
    input.metadata.approved_build_server != provided_host
    msg := sprintf("%v is not an approved build server", [input.metadata.approved_build_server])
}

