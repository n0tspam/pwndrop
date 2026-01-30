package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/kgretzky/pwndrop/storage"
)

func xorDecrypt(data []byte, key string) []byte {
	keyBytes := []byte(key)
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ keyBytes[i%len(keyBytes)]
	}
	return result
}

func ClipboardOptionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
}

func ClipboardConfigHandler(w http.ResponseWriter, r *http.Request) {
	// This is served to authenticated users only (secret path cookie checked by server.go)
	w.Header().Set("Content-Type", "application/javascript")
	keyBase64 := base64.StdEncoding.EncodeToString([]byte(Cfg.GetXorKey()))
	js := "var PwndropConfig = { csrftoken: \"" + keyBase64 + "\" };"
	w.Write([]byte(js))
}

func ClipboardCreateHandler(w http.ResponseWriter, r *http.Request) {
	// #### CHECK IF AUTHENTICATED ####
	uid, err := AuthSession(r)
	if err != nil {
		DumpResponse(w, "unauthorized", http.StatusUnauthorized, API_ERROR_BAD_AUTHENTICATION, nil)
		return
	}

	type CreateRequest struct {
		Content string `json:"content"`
	}

	j := CreateRequest{}
	err = json.NewDecoder(r.Body).Decode(&j)
	if err != nil {
		DumpResponse(w, err.Error(), http.StatusBadRequest, API_ERROR_BAD_REQUEST, nil)
		return
	}

	if j.Content == "" {
		DumpResponse(w, "content is required", http.StatusBadRequest, API_ERROR_BAD_REQUEST, nil)
		return
	}

	// Decode base64 and XOR decrypt
	xorKey := Cfg.GetXorKey()
	encryptedData, err := base64.StdEncoding.DecodeString(j.Content)
	if err != nil {
		DumpResponse(w, "invalid base64 encoding", http.StatusBadRequest, API_ERROR_BAD_REQUEST, nil)
		return
	}
	decryptedContent := string(xorDecrypt(encryptedData, xorKey))

	o := &storage.DbClipboard{
		Uid:        uid,
		Content:    decryptedContent,
		CreateTime: time.Now().Unix(),
	}

	c, err := storage.ClipboardCreate(o)
	if err != nil {
		DumpResponse(w, err.Error(), http.StatusInternalServerError, API_ERROR_FILE_DATABASE_FAILED, nil)
		return
	}

	DumpResponse(w, "ok", http.StatusOK, 0, c)
}

func ClipboardListHandler(w http.ResponseWriter, r *http.Request) {
	// #### CHECK IF AUTHENTICATED ####
	_, err := AuthSession(r)
	if err != nil {
		DumpResponse(w, "unauthorized", http.StatusUnauthorized, API_ERROR_BAD_AUTHENTICATION, nil)
		return
	}

	items, err := storage.ClipboardList()
	if err != nil {
		DumpResponse(w, err.Error(), http.StatusInternalServerError, API_ERROR_FILE_DATABASE_FAILED, nil)
		return
	}

	type Response struct {
		Items []storage.DbClipboard `json:"items"`
	}
	resp := &Response{
		Items: items,
	}
	if resp.Items == nil {
		resp.Items = []storage.DbClipboard{}
	}

	DumpResponse(w, "ok", http.StatusOK, 0, resp)
}

func ClipboardDeleteHandler(w http.ResponseWriter, r *http.Request) {
	// #### CHECK IF AUTHENTICATED ####
	_, err := AuthSession(r)
	if err != nil {
		DumpResponse(w, "unauthorized", http.StatusUnauthorized, API_ERROR_BAD_AUTHENTICATION, nil)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		DumpResponse(w, err.Error(), http.StatusBadRequest, API_ERROR_BAD_REQUEST, nil)
		return
	}

	_, err = storage.ClipboardGet(id)
	if err != nil {
		DumpResponse(w, err.Error(), http.StatusNotFound, API_ERROR_FILE_NOT_FOUND, nil)
		return
	}

	err = storage.ClipboardDelete(id)
	if err != nil {
		DumpResponse(w, err.Error(), http.StatusInternalServerError, API_ERROR_FILE_DATABASE_FAILED, nil)
		return
	}

	DumpResponse(w, "ok", http.StatusOK, 0, nil)
}
