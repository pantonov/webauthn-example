package main

import (
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "github.com/gorilla/mux"
    "github.com/pantonov/webauthn_sign"
    "log"
    "net/http"
)

func getData(m map[string]string, name string) []byte {
    r, _ := base64.RawURLEncoding.DecodeString(m[name])
    return r
}

func BeginSign(w http.ResponseWriter, r *http.Request) {

    // get username
    vars := mux.Vars(r)
    username := vars["username"]
    dataHash := sha256.Sum256(getData(vars,"data"))

    // get user
    user, err := userDB.GetUser(username)

    // user doesn't exist
    if err != nil {
        log.Println(err.Error())
        JsonResponse(w, err.Error(), http.StatusBadRequest)
        return
    }
    options, _ := webauthn_sign.PrepareSignatureAssertion(webAuthn, dataHash[:], user)
    if err != nil {
        log.Println("PrepareSignatureAssertion: ", err.Error())
        JsonResponse(w, err.Error(), http.StatusInternalServerError)
        return
    }

    JsonResponse(w, options, http.StatusOK)
}

func Sign(w http.ResponseWriter, r *http.Request) {
    signature, err := webauthn_sign.ParseSignatureCredentialResponse(r)
    if err != nil {
        fmt.Println(err.Error())
        JsonResponse(w, err.Error(), http.StatusBadRequest)
        return
    }
    // handle successful login
    JsonResponse(w, signature, http.StatusOK)
}

func Verify(w http.ResponseWriter, r *http.Request) {

    // get username
    vars := mux.Vars(r)
    username := vars["username"]
    signatureJson := getData(vars, "signature")
    data     := getData(vars, "data")

    // get user
    user, err := userDB.GetUser(username)

    // user doesn't exist
    if err != nil {
        log.Println(err.Error())
        JsonResponse(w, err.Error(), http.StatusBadRequest)
        return
    }
    credential := user.credentials[0]

    log.Println("signature: ", string(signatureJson))

    // Decode signature from json
    signature := webauthn_sign.Signature{}
    if err := json.Unmarshal(signatureJson, &signature); nil != err {
        log.Println(err.Error())
        JsonResponse(w, err.Error(), http.StatusBadRequest)
        return
    }

    valid, err := signature.VerifySha256(credential.PublicKey, data)
    if nil != err {
        log.Println("checksig error", err)
        JsonResponse(w, err.Error(), http.StatusBadRequest)
        return
    }
    if !valid {
        log.Println("signature verify failed")
        JsonResponse(w, "Signature verification failed!", http.StatusOK)
        return
    } else {
        log.Println("Signature verify OK!")
        JsonResponse(w, "Signature verify OK!", http.StatusOK)
    }


}