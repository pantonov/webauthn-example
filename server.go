package main

import (
    "bytes"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "github.com/duo-labs/webauthn/protocol/webauthncose"
    "log"
    "net/http"
    "strings"

    "github.com/duo-labs/webauthn.io/session"
    "github.com/duo-labs/webauthn/protocol"
    "github.com/duo-labs/webauthn/webauthn"
    "github.com/gorilla/mux"
)

var webAuthn *webauthn.WebAuthn
var userDB *userdb
var sessionStore *session.Store

func main() {

	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Foobar Corp.",     // Display Name for your site
		RPID:          "localhost",        // Generally the domain name for your site
		RPOrigin:      "http://localhost", // The origin URL for WebAuthn requests
		// RPIcon: "https://duo.com/logo.png", // Optional icon URL for your site
	})

	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}

	userDB = DB()

	sessionStore, err = session.NewStore()
	if err != nil {
		log.Fatal("failed to create session store:", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/register/begin/{username}", BeginRegistration).Methods("GET")
	r.HandleFunc("/register/finish/{username}", FinishRegistration).Methods("POST")
	r.HandleFunc("/login/begin/{username}", BeginLogin).Methods("GET")
	r.HandleFunc("/login/finish/{username}", FinishLogin).Methods("POST")

    r.HandleFunc("/beginsign/{username}/{sigdata}", BeginSign).Methods("GET")
    r.HandleFunc("/sign/{username}/{sigdata}",      Sign).Methods("POST")

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./")))

	serverAddress := ":8080"
	log.Println("starting server at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {

	// get username/friendly name
	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist, create new user
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = NewUser(username, displayName)
		userDB.PutUser(user)
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
	}

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := webAuthn.BeginRegistration(
		user,
		registerOptions,
	)

	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("registration", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("registration", r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user.AddCredential(*credential)

	jsonResponse(w, "Registration Success", http.StatusOK)
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}


func FinishLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	_, err = webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// handle successful login
	jsonResponse(w, "Login Success", http.StatusOK)
}

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	_,_ = fmt.Fprintf(w, "%s", dj)
}

func BeginSign(w http.ResponseWriter, r *http.Request) {

    // get username
    vars := mux.Vars(r)
    username := vars["username"]
    sighash := sha256.Sum256([]byte(vars["sigdata"]))

    // get user
    user, err := userDB.GetUser(username)

    // user doesn't exist
    if err != nil {
        log.Println(err)
        jsonResponse(w, err.Error(), http.StatusBadRequest)
        return
    }

    // generate PublicKeyCredentialRequestOptions, session data
    options, sessionData, err := BeginSignReq(webAuthn, sighash[:], user)
    if err != nil {
        log.Println("beginSignReq: " + err.Error())
        jsonResponse(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // store session data as marshaled JSON
    err = sessionStore.SaveWebauthnSession("signature", sessionData, r, w)
    if err != nil {
        log.Println("saveSigession: ", err.Error())
        jsonResponse(w, err.Error(), http.StatusInternalServerError)
        return
    }

    jsonResponse(w, options, http.StatusOK)
}


func BeginSignReq(wa *webauthn.WebAuthn, sighash []byte, user *User) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {

    if len(sighash) < 16 || len(sighash) > 64 {
        return nil, nil, protocol.ErrBadRequest.WithDetails("Invalid signature hash length")
    }
    credentials := user.WebAuthnCredentials()

    if len(credentials) == 0 { // If the user does not have any credentials, we cannot do login
        return nil, nil, protocol.ErrBadRequest.WithDetails("Found no credentials for user")
    }

    var allowedCredentials = make([]protocol.CredentialDescriptor, len(credentials))

    for i, credential := range credentials {
        var credentialDescriptor protocol.CredentialDescriptor
        credentialDescriptor.CredentialID = credential.ID
        credentialDescriptor.Type = protocol.PublicKeyCredentialType
        allowedCredentials[i] = credentialDescriptor
    }

    requestOptions := protocol.PublicKeyCredentialRequestOptions{
        Challenge:          sighash,
        Timeout:            wa.Config.Timeout,
        RelyingPartyID:     wa.Config.RPID,
        UserVerification:   wa.Config.AuthenticatorSelection.UserVerification,
        AllowedCredentials: allowedCredentials,
    }
    newSessionData := webauthn.SessionData{
        Challenge:            base64.RawURLEncoding.EncodeToString(sighash),
        UserID:               user.WebAuthnID(),
        AllowedCredentialIDs: requestOptions.GetAllowedCredentialIDs(),
        UserVerification:     requestOptions.UserVerification,
    }

    response := protocol.CredentialAssertion{Response: requestOptions}

    return &response, &newSessionData, nil
}

type Signature struct {
    AuthenticatorData protocol.URLEncodedBase64 `json:"ad"`
    ClientData        protocol.URLEncodedBase64 `json:"cd"`
    SignatureData     protocol.URLEncodedBase64 `json:"s"`
}

func Sign(w http.ResponseWriter, r *http.Request) {

    // get username
    vars := mux.Vars(r)
    username := vars["username"]

    // get user
    user, err := userDB.GetUser(username)

    // user doesn't exist
    if err != nil {
        log.Println("getuser error:", err)
        jsonResponse(w, err.Error(), http.StatusBadRequest)
        return
    }

    // load the session data
    _, err = sessionStore.GetWebauthnSession("signature", r)
    if err != nil {
        log.Println("getsession error: ", err.Error())
        jsonResponse(w, err.Error(), http.StatusBadRequest)
        return
    }

    credential := user.credentials[0]

    // in an actual implementation, we should perform additional checks on
    // the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
    // and then increment the credentials counter

    //bodyData, _ := ioutil.ReadAll(r.Body)
    //r.Body = ioutil.NopCloser(bytes.NewReader(bodyData))



    //credential, err := webAuthn.FinishLogin(user, sessionData, r)
    //if err != nil {
    //    log.Println("FinishLogin: ", err.Error())
    //    jsonResponse(w, err.Error(), http.StatusBadRequest)
    //    return
   // }
    //r.Body = ioutil.NopCloser(bytes.NewReader(bodyData))

    parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
    if err != nil {
        fmt.Println("ParseResponse: " + err.Error())
        jsonResponse(w, err.Error(), http.StatusBadRequest)
        return
    }
    //log.Println(parsedResponse)
    signature := Signature {
        AuthenticatorData: parsedResponse.Raw.AssertionResponse.AuthenticatorData,
        ClientData:        parsedResponse.Raw.AssertionResponse.ClientDataJSON,
        SignatureData:     parsedResponse.Response.Signature,
    }
    sighash := sha256.Sum256([]byte(vars["sigdata"]))

    valid, err := checkSignature(webAuthn.Config, &signature, credential.PublicKey, sighash[:])

    if nil != err {
        log.Println("checksig error", err)
        jsonResponse(w, err.Error(), http.StatusBadRequest)
        return
    }
    if !valid {
        log.Println("signature verify failed")
        jsonResponse(w, "signature verification failed", http.StatusBadRequest)
        return
    } else {
        log.Println("Signature verify OK!")
    }

    msigjs, _ := json.Marshal(signature)
    msig := string(msigjs)
    log.Println(msig)
    // handle successful login
    jsonResponse(w, msig, http.StatusOK)
}

func checkSignature(config *webauthn.Config, signature *Signature, pubkey []byte,  sigdata []byte) (bool, error) {

    // to: unmarshal authenticatordata, check rpid hash
    // rpIDHash := sha256.Sum256([]byte(config.RPID))
    collectedClientData := protocol.CollectedClientData{}
    if err := json.Unmarshal(signature.ClientData, &collectedClientData); nil != err {
        return false, errors.New("unmarshalling ccd: " + err.Error())
    }
    var challenge protocol.URLEncodedBase64
    if err := challenge.UnmarshalJSON([]byte(collectedClientData.Challenge)); nil != err {
        return false, errors.New("unmarshalling challenge: " + err.Error())
    }
    if bytes.Compare(challenge, sigdata) != 0 {
        log.Println("challenge mismatch")
        return false, nil
    }
    clientDataHash := sha256.Sum256(signature.ClientData)
    sigData := append(signature.AuthenticatorData, clientDataHash[:]...)

    key, err := webauthncose.ParsePublicKey(pubkey)
    if nil != err {
        return false, errors.New("pubkey parse error: " + err.Error())
    }
    valid, err := webauthncose.VerifySignature(key, sigData, signature.SignatureData)
    if nil != err {
        return false, errors.New("verify signature error: " + err.Error())
    }
    return valid, nil
}
