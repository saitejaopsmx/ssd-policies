package opsmx

default allow = false

deny{

    input.metadata.build_image_sha != input.metadata.image_sha
}
