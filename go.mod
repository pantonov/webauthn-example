module github.com/pantonov/webauthn-example

go 1.17

replace github.com/pantonov/webauthn_sign => ../webauthn_sign

require (
	github.com/duo-labs/webauthn v0.0.0-20211221191814-a22482edaa3b
	github.com/duo-labs/webauthn.io v0.0.0-20190926134215-35f44a73518f
	github.com/gorilla/mux v1.7.1
	github.com/pantonov/webauthn_sign v0.0.0-00010101000000-000000000000
)

require (
	github.com/cloudflare/cfssl v0.0.0-20190726000631-633726f6bcb7 // indirect
	github.com/fxamacker/cbor/v2 v2.2.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.1.0 // indirect
	github.com/google/certificate-transparency-go v1.0.21 // indirect
	github.com/gorilla/context v1.1.1 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/gorilla/sessions v1.1.3 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.1.2 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/sirupsen/logrus v1.4.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.0.0-20190701094942-4def268fd1a4 // indirect
	golang.org/x/sys v0.0.0-20190726091711-fc99dfbffb4e // indirect
)
