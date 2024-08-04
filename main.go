package main

import (
	"fmt"
	"net/http"
	"sztafeta/handlers"
)

func main() {
	router := handlers.NewRouter()

	fmt.Println("Serwer działa na porcie 8080")
	err := http.ListenAndServe(":8080", router)
	if err != nil {
		fmt.Println("Błąd przy uruchamianiu serwera:", err)
	}
}
