package opsmx

default allow = false

deny[msg]{

    input.metadata.approved_build_user != input.metadata.build_user
    msg := sprintf("%v is not an approved build user", [input.metadata.approved_build_user])
}


