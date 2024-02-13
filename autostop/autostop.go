package main

import (
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/sbinet/pstree"
)

func FindProc(tree *pstree.Tree, name string, parent int) *pstree.Process {
	for _, p := range tree.Procs {
		if p.Stat.Ppid == parent && p.Name == name {
			return &p
		}
	}
	return nil
}

func main() {
	d, err := time.ParseDuration(os.Args[1])
	if err != nil {
		panic(err)
	}
	lastActivity := time.Now()
	log.Println("Waiting for", d, "of inactivity")
	for lastActivity.Add(d).After(time.Now()) {
		time.Sleep(10 * time.Second)
		tree, err := pstree.New()
		if err != nil {
			continue
		}
		sshd := FindProc(tree, "sshd", 1)
		found := false
		if sshd != nil && len(sshd.Children) > 0 {
			//log.Println("Found ssh connection")
			lastActivity = time.Now()
			found = true
		}
		for _, rootProcId := range tree.Procs[1].Children {
			screen := tree.Procs[rootProcId]
			if screen.Name != "screen" && screen.Name != "tmux: server" {
				continue
			}
			// Screen has to be running something (like a shell) that is running something else
			if len(screen.Children) > 0 && len(tree.Procs[screen.Children[0]].Children) > 0 {
				lastActivity = time.Now()
				found = true
			} else {
			}
		}
		if !found {
			log.Println("No activity found.", time.Until(lastActivity.Add(d)), "remaining.")
		}
	}
	log.Println("No activity for", d)
	if len(os.Args[2:]) > 0 {
		log.Println("Running", strings.Join(os.Args[2:], " "))
		cmd := exec.Command(os.Args[2], os.Args[3:]...)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatal(err)
		}
	}
}
