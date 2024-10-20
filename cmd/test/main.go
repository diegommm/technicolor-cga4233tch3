package main

import (
	"context"
	"fmt"

	"github.com/diegommm/technicolor-cga4233tch3/pkg/client"
)

func noerr(err error, msg string) {
	if err != nil {
		panic(fmt.Sprintf("%s: %v", msg, err))
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c, err := client.New(client.Params{
		Username:            "surface8710",
		Password:            "Unchain/Bogged2/Pastor",
		TryDefaultAuthFirst: true,
		SetAuthIfDefault:    true,
	})
	noerr(err, "create new client")

	err = c.Login(ctx)
	noerr(err, "initial login")

	/*
		err = c.SetAuth(ctx, "custadmin", "cga4233")
		noerr(err, "set auth")
	*/
}
