module main

go 1.14

require (
	echo v0.0.0
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/google/go-tpm v0.2.0 // indirect
	github.com/googleapis/gax-go v1.0.3 // indirect
	github.com/hashicorp/vault/api v1.0.4 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/salrashid123/oauth2 v0.0.0-20200503195646-e37a24dfdeb3
	golang.org/x/net v0.0.0-20200324143707-d3edc9973b7e
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	google.golang.org/api v0.23.0
	google.golang.org/grpc v1.28.0
)

replace echo => ./src/echo
