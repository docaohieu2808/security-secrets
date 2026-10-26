package lib.images

# Registry prefixes the organisation allows. Override in environment-specific bundles.
approved_registries := {
	"gcr.io/my-org/",
	"registry.company.com/",
	"ghcr.io/my-org/",
	"public.ecr.aws/amazonlinux/",
	"docker.io/library/",
}

from_approved_registry(image) if {
	some registry in approved_registries
	startswith(image, registry)
}

# A digest-pinned reference is immutable, whatever the tag says.
has_digest(image) if contains(image, "@sha256:")

# image_tag(image): the tag of the last path segment ("registry:5000/app" has no tag).
image_tag(image) := tag if {
	not has_digest(image)
	parts := split(image, "/")
	last := parts[count(parts) - 1]
	contains(last, ":")
	tag := split(last, ":")[1]
}

# is_mutable(image): no digest, and the tag is missing or `latest`.
is_mutable(image) if {
	not has_digest(image)
	not image_tag(image)
}

is_mutable(image) if image_tag(image) == "latest"

# extract_registry(image): "gcr.io/project/image:tag" -> "gcr.io"; no hostname -> "docker.io".
extract_registry(image) := parts[0] if {
	parts := split(image, "/")
	count(parts) > 1
	some marker in [".", ":"]
	contains(parts[0], marker)
} else := parts[0] if {
	parts := split(image, "/")
	count(parts) > 1
	parts[0] == "localhost"
} else := "docker.io"
