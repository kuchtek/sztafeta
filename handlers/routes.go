package handlers

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("Witaj w mojej aplikacji!"))
	if err != nil {
		fmt.Println("Error making request:", err)
	}
}

func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", HomeHandler).Methods("GET")
	return router
}
