package opsmx

default allow = false

build_url = input.metadata.build_url
deny[msg]{
    count(input.metadata.parent_repo) != 0
    msg := sprintf("%v is a forked repo from %v", [input.metadata.repository, input.metadata.parent_repo])
}

