package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

const usage = `

spid: simple portable intrusion detection

usage: spid [-db dbpath] [-config configpath] command

commands:

init - initialize a new database using the supplied config and writing to the supplied dbpath
scan - use the supplied database and run a scan, displaying any new events

`

func main() {
	configPath := flag.String("config", "config.json", "path to the sentinel configuration")
	dbPath := flag.String("db", "spid.db", "path to the spid atabase")
	flag.Parse()

	if len(flag.Args()) != 1 {
		fmt.Println(usage)
		os.Exit(-1)
	}

	cmd := flag.Args()[0]
	var err error
	switch cmd {
	case "init":
		err = initCmd(*configPath, *dbPath)
	case "scan":
		err = scanCmd(*dbPath)
	default:
		fmt.Println("Command not recognized.")
		fmt.Println(usage)
		os.Exit(-1)
	}
	if err != nil {
		log.Fatal(err)
	}
}
