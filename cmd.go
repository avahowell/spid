package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/avahowell/spid/sentinel"

	"github.com/howeyc/gopass"
)

func initCmd(configPath string, dbPath string) error {
	f, err := os.Open(configPath)
	if err != nil {
		return err
	}
	defer f.Close()
	var config sentinel.Config
	err = json.NewDecoder(f).Decode(&config)
	if err != nil {
		return err
	}
	fmt.Println("Verifying we can read WatchFiles...")
	for _, wf := range config.WatchFiles {
		f, err := os.Open(wf)
		if err != nil {
			fmt.Printf("Could not open %v: %v\n", wf, err)
			os.Exit(-1)
		}
		fmt.Printf("%v -> SUCCESS\n", wf)
		f.Close()
	}
	fmt.Println("Success! Setting up spid db")
	s := sentinel.New(config)
	fmt.Print("Encryption password: ")
	pass, err := gopass.GetPasswd()
	if err != nil {
		return err
	}
	fmt.Print("Again, please: ")
	pass2, err := gopass.GetPasswd()
	if err != nil {
		return err
	}
	if string(pass) != string(pass2) {
		return err
	}
	err = s.Save(dbPath, string(pass))
	if err != nil {
		return err
	}
	fmt.Println("successfully created", dbPath, ". you can now safely delete config.json and use [spid scan].")
	return nil
}

func scanCmd(dbPath string) error {
	fmt.Printf("Password for %v: ", dbPath)
	pass, err := gopass.GetPasswd()
	if err != nil {
		return err
	}
	s, err := sentinel.Open(dbPath, string(pass))
	if err != nil {
		return err
	}
	evs, err := s.Scan()
	if err != nil {
		return err
	}
	fmt.Printf("\nScan results for %v: \n\n", time.Now().String())
	if len(evs) == 0 {
		fmt.Println("No changes detected.")
	}
	for _, ev := range evs {
		fmt.Printf("[%v %v] %v -> %v\n", ev.Evtype, ev.File, ev.OrigChecksum, ev.NewChecksum)
	}
	fmt.Println("\nPrior scans:")
	for _, sc := range s.PriorScans {
		fmt.Printf("\n[%v]: \n", sc.Timestamp.String())
		if len(sc.Events) == 0 {
			fmt.Println("    No changes detected.")
		}
		for _, ev := range sc.Events {
			fmt.Printf("    [%v %v] %v -> %v\n", ev.Evtype, ev.File, ev.OrigChecksum, ev.NewChecksum)
		}
	}
	err = s.Save(dbPath, string(pass))
	if err != nil {
		return err
	}
	return nil
}
