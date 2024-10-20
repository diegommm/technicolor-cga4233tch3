package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"

	"github.com/diegommm/technicolor-cga4233tch3/pkg/client"
)

func must[T any](v T, err error) func(desc string) T {
	return func(desc string) T {
		if err != nil {
			panic(fmt.Errorf("%s: %w", desc, err))
		}
		return v
	}
}

func main() {
	stdin := bufio.NewScanner(os.Stdin)

	fmt.Printf("Enter the password: ")
	pass := must(readline(stdin))("read password")

	fmt.Printf("Enter the value of `salt`: ")
	salt := must(readline(stdin))("read `salt`")

	fmt.Printf("Enter the value of `saltwebui`: ")
	saltWebUI := must(readline(stdin))("read `saltwebui`")

	fmt.Println()
	fmt.Println(client.DefaultDerivePasswordWebUI(pass, salt, saltWebUI))
}

func readline(scanner *bufio.Scanner) ([]byte, error) {
	if !scanner.Scan() {
		return nil, errors.New("no more tokens")
	}
	return scanner.Bytes(), scanner.Err()
}
