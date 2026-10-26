package lib.images_test

import data.lib.images

test_approved_registry if {
	images.from_approved_registry("ghcr.io/my-org/app:1.0")
	not images.from_approved_registry("evil.example/app:1.0")
}

test_digest if {
	images.has_digest("app@sha256:abc")
	not images.has_digest("app:1.0")
}

test_image_tag if {
	images.image_tag("nginx:1.27") == "1.27"
	images.image_tag("registry.example:5000/team/app:2.0") == "2.0"
	not images.image_tag("registry.example:5000/app")
	not images.image_tag("nginx")
}

test_is_mutable if {
	images.is_mutable("nginx")
	images.is_mutable("nginx:latest")
	images.is_mutable("registry.example:5000/app")
	not images.is_mutable("nginx:1.27")
	not images.is_mutable("nginx:latest@sha256:abc")
}

test_extract_registry if {
	images.extract_registry("gcr.io/project/image:tag") == "gcr.io"
	images.extract_registry("registry.example:5000/app") == "registry.example:5000"
	images.extract_registry("localhost/app") == "localhost"
	images.extract_registry("nginx:1.27") == "docker.io"
	images.extract_registry("library/nginx") == "docker.io"
}
