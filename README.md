
# gRPC Authentication with Cloud Run

>> Update `5/10/20`:  [google.golang.org/api/idtoken](https://pkg.go.dev/google.golang.org/api@v0.23.0/idtoken) now contains OIDC tokens support; use that instead of `github.com/salrashid123/oauth2/google`

A couple months back I was happy to assist the [Cloud Run](https://cloud.google.com/run/) (managed) team in validating gRPC support on that platform.  The testing/validation covered writing a simple deployable gRPC client and server that also performed OpenIDConnect (OIDC) Authentication over gRPC (i.,e. Cloud Run Authentication).   In the course of developing that, i gained an understanding of how gRPC authentication headers are handled and manged directly with gRPC.   This article explains how to connect to a secure gRPC service running on Cloud Run using native gRPC library constructs.

The links cited in the Reference section discusses gRPC on Cloud Run but these do not cover either authentication at all or do not specify authentication using gRPC-centric constructs with Google Cloud Auth client libraries.

This article covers a simple client-server you can deploy on Cloud run that includes gRPC authentication _using google cloud credentials_ .   We specifically use `ServiceAccount Credentials` but the library cited below will work while running on GCE, GKE or even on Cloud RUn itself.

![images/icon.png](images/icon.png)

---

### OIDC Basics for GCP Services and gRPC

This article does not go into details about OpenID Connect tokens and how to use them with gRPC and GCP.  However, as background please see

- [gRPC Authentication with Google OpenID Connect tokens](https://medium.com/google-cloud/grpc-authentication-with-google-openid-connect-tokens-812ceb3e5c41)
  - [https://github.com/salrashid123/grpc_google_id_tokens](https://github.com/salrashid123/grpc_google_id_tokens)
- [Authenticating using Google OpenID Connect Tokens](https://medium.com/google-cloud/authenticating-using-google-openid-connect-tokens-e7675051213b)

The links above shows how to acquire Google OIDC tokens that you can use for a variety of GCP services or even standalone. One thing noted that not all google cloud auth libraries provide interfaces to get OIDC tokens.  At the time of writing, only google-auth libraries for java and python are supported with nodejs pending and golang yet to be officially implemented.  Furthermore, most of those languages that do support acquiring OIDC token happen to also support automatic injection into gRPC calls. 

For golang (as in the code in this article), it does not yet 1) support getting google OIDC tokens and 2) using those tokens in a library directly with gRPC.  This article provides an _unsupported_ implementation of both (from google's official perspective atleast):

- ["google.golang.org/api/idtoken"](https://pkg.go.dev/google.golang.org/api@v0.23.0/idtoken)  << use this!
- [https://github.com/salrashid123/oauth2#usage-idtoken](https://github.com/salrashid123/oauth2#usage-idtoken)

Both library sets above for golang also implements a specific [TokenSource](https://godoc.org/golang.org/x/oauth2#TokenSource) that uses a source google identity to get its OIDC token as yet another standard TokenSource or Credentials.  For implementation details, see [IdTokenSource](https://github.com/salrashid123/oauth2/blob/master/google/idtoken.go#L46). 

Furthermore, that TokenSource also implements the interfaces that gRPC understands _natively_.   What that means is gRPC clients if given that tokens source will automatically acquire, use, referesh and manage the lifecycle of the OIDC token!

For details, the specific interface that does that for gRPC is:

```golang
// NewIDTokenRPCCredential returns a crdential object for use with gRPC clients
func NewIDTokenRPCCredential(ctx context.Context, tokenSource oauth2.TokenSource) (credentials.PerRPCCredentials, error) 

// GetRequestMetadata gets the request metadata as a map from a TokenSource.
func (ts TokenSource) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error)

// RequireTransportSecurity indicates whether the credentials requires transport security.
func (ts TokenSource) RequireTransportSecurity() bool
```

As an example of direct usage of an IDToken with grpc _native_ constructs like `grpc.WithPerRPCCredentials()`:

```golang
import "google.golang.org/api/idtoken"
...
...
	idTokenSource, err := idtoken.NewTokenSource(ctx, targetAudience, idtoken.WithCredentialsFile(serviceAccount))
	if err != nil {
		log.Fatalf("unable to create TokenSource: %v", err)
	}
	tok, err := idTokenSource.Token()
	if err != nil {
		log.Fatal(err)
	}

        ce := credentials.NewTLS(&tlsCfg)
		conn, err = grpc.Dial(*address,
			grpc.WithTransportCredentials(ce),
			grpc.WithPerRPCCredentials(grpcTokenSource{
				TokenSource: oauth.TokenSource{
					idTokenSource,
				},
			}),
		)
```

> For equivalent samples in other languages see [gRPC Authentication with Google OpenID Connect tokens](https://github.com/salrashid123/grpc_google_id_tokens).

Anyway, lets go directly into the details


I'm assuming you have Cloud Run setup and relatively above with gRPC and the auth concepts cited above


#### Setup Env Vars 

```bash
    export PROJECT_ID=`gcloud config get-value core/project`
    gcloud config set run/region us-central1
    gcloud config set run/platform managed
```

#### Build and deploy gRPC Server Image

```bash
    docker build -t gcr.io/$PROJECT_ID/grpc_run_serve -f Dockerfile.server .
    docker push gcr.io/$PROJECT_ID/grpc_run_serve
    gcloud beta run deploy grpc --image gcr.io/$PROJECT_ID/grpc_run_serve
```

#### Create Client SA

Now create the service account that will have access to invoke the Cloud Run service

```bash
    mkdir -p certs
    cd certs
    gcloud iam service-accounts create grpc-client-account --display-name "gRPC Client Service Account"
    gcloud iam service-accounts keys create certs/grpc_client.json --iam-account=grpc-client-account@$PROJECT_ID.iam.gserviceaccount.com
```

#### Set IAM Permission for `roles/run.invoker`:

```bash
cat <<EOT >> iam_policy.json
bindings:
- members:
  - serviceAccount:grpc-client-account@$PROJECT_ID.iam.gserviceaccount.com
  role: roles/run.invoker
version: 1
EOT

gcloud beta run services set-iam-policy grpc iam_policy.json 
```

## Build Client

At this point, the gRPC service is secure by default and would require an OIDC token with the correct `audience` field and IAM permissions to get through

The audience filed for cloud run needs to be the fully qualified name with the protocol (custom domain aud fields is currently not supported)

```bash
    export AUDIENCE=`gcloud beta run services describe grpc2 --format="value(status.url)"`
    export ADDRESS=`echo $AUDIENCE |  awk -F[/:] '{print $4}'`
    echo $AUDIENCE
    echo $ADDRESS
```

On the root folder of this repo, run:

```
docker build -t gcr.io/$PROJECT_ID/grpc_run_client -f Dockerfile.client .
```

## RUN gRPC Client

Now run the grpc client and specify the serviceAccount json file that is mounted inside the container (note: you should cd to the root of this repo so that the path to `certs/` is mounted):

```
docker run -v `pwd`/certs:/certs -t gcr.io/$PROJECT_ID/grpc_run_client --address $ADDRESS:443 --usetls=true  --servername $ADDRESS --audience $AUDIENCE --serviceAccount /certs/grpc_client.json
```

The output of `grpc_run_client` will show the OIDC token sent to the cloud run instance which you can decode at [jwt.io](jwt.io).  Note the `aud:`, `email` and `iss` fields 

```json
{
  "iss": "https://accounts.google.com",
  "aud": "https://grpc-6w42z6vi3q-uc.a.run.app",
  "azp": "grpc-client-account@mineral-minutia-820.iam.gserviceaccount.com",
  "sub": "101659512549165144150",
  "email": "grpc-client-account@mineral-minutia-820.iam.gserviceaccount.com",
  "email_verified": true,
  "iat": 1572983749,
  "exp": 1572987349
}
```

The second portion is 5 unary responses back from the GRPC service that displays the `K_REVISION` env variable from Cloud RUn

```
2019/11/05 20:52:14 RPC Response: 0 message:"Hello unary RPC msg   from K_REVISION grpc-tnslx" 
2019/11/05 20:52:15 RPC Response: 1 message:"Hello unary RPC msg   from K_REVISION grpc-tnslx" 
2019/11/05 20:52:16 RPC Response: 2 message:"Hello unary RPC msg   from K_REVISION grpc-tnslx" 
2019/11/05 20:52:17 RPC Response: 3 message:"Hello unary RPC msg   from K_REVISION grpc-tnslx" 
2019/11/05 20:52:18 RPC Response: 4 message:"Hello unary RPC msg   from K_REVISION grpc-tnslx" 
```

The final output is a buffered form Server-side Streaming messages back (i.,e the server sends back two responses back on the single request).
At the time of writing `11/5/19`, server streaming is _not_ officially supported as its not true streaming but a buffered response anyway 

```
2019/11/05 20:52:18 Stream Header: %!(EXTRA metadata.MD=map[alt-svc:[quic=":443"; ma=2592000; v="46,43",h3-Q049=":443"; ma=2592000,h3-Q048=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000] content-type:[application/grpc] streamheaderkey:[val] x-cloud-trace-context:[7928b8ab5aa6b2dc759ca6ff7fa5bb4c] date:[Tue, 05 Nov 2019 20:52:19 GMT] server:[Google Frontend] content-length:[52]])

2019/11/05 20:52:18 Message: %!(EXTRA string=Msg1 Stream RPC msg)

2019/11/05 20:52:18 Stream Header: %!(EXTRA metadata.MD=map[date:[Tue, 05 Nov 2019 20:52:19 GMT] server:[Google Frontend] content-length:[52] alt-svc:[quic=":443"; ma=2592000; v="46,43",h3-Q049=":443"; ma=2592000,h3-Q048=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000] content-type:[application/grpc] streamheaderkey:[val] x-cloud-trace-context:[7928b8ab5aa6b2dc759ca6ff7fa5bb4c]])

2019/11/05 20:52:18 Message: %!(EXTRA string=Msg2 Stream RPC msg)

2019/11/05 20:52:18 Stream Trailer:  map[]
```


>> Note client->gRPC server side streaming for Cloud Run (managed) is _not_ currently supported


enjoy grpc-ing!


### References
- Cloud Run
  - [Serverless gRPC with Cloud Run](https://medium.com/@petomalina/%EF%B8%8Fserverless-grpc-with-cloud-run-bab3622a47da)
  - [gRPC Authentication on Cloud Run](https://ahmet.im/blog/grpc-auth-cloud-run/)

- Misc
  - [Calling Cloud Composer to Cloud Functions and back again, securely](https://medium.com/google-cloud/calling-cloud-composer-to-cloud-functions-and-back-again-securely-8e65d783acce)
  - [Automatic OIDC: Using Cloud Scheduler, Tasks, and PubSub to make authenticated calls to Cloud Run, Cloud Functions or your Server](https://medium.com/google-cloud/automatic-oidc-using-cloud-scheduler-tasks-and-pubsub-to-make-authenticated-calls-to-cloud-run-de9e7e9cec3f)

  - [Authorizing access to Cloud Run for Anthos deployed on GKE services using Istio](https://cloud.google.com/solutions/authorizing-access-to-cloud-run-on-gke-services-using-istio)
  - [Authenticating end users of Cloud Run for Anthos deployed on GKE services using Istio and Identity Platform](https://cloud.google.com/solutions/authenticating-cloud-run-on-gke-end-users-using-istio-and-identity-platform)

### Appendix

#### Openssl CA

I added in a sample SSL certificate set into the images which are not used since Cloud Run automatically does SSL management for you.  However, if you wanted to run this over Self-Signed certs, [here is a setup to create your own CA](https://github.com/salrashid123/squid_proxy#generating-new-ca
) (note, you will need to edit `openssl.conf` here and specify the SNI settings (i.,e override value in 
```
    [alt_names]
    DNS.1 = grpc.domain.com
```

