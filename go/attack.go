package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

func main() {
	var wg sync.WaitGroup
	url := "http://192.168.1.195/app" // Replace with your server URL
	requests := 1000                  // Number of requests you want to send

	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := http.Get(url)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			fmt.Println("Requested", url)
		}()
		time.Sleep(10 * time.Millisecond) // Adjust the timing to control request rate
	}

	wg.Wait()
	fmt.Println("Load test completed")
}
