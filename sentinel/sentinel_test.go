package sentinel

import (
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// createRandFile is a helper function used to create the file at path with
// size random bytes
func createRandFile(path string, size int64) (*os.File, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	_, err = io.CopyN(f, rand.Reader, size)
	return f, err
}

// TestWatchFileDirectory verifies that the sentinel watches specified
// directories recursively.
func TestWatchFileDirectory(t *testing.T) {
	dir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	var fileHandles []*os.File
	for _, subfile := range []string{"file1", "file2"} {
		f, err := createRandFile(filepath.Join(dir, subfile), 1024)
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(f.Name())
		fileHandles = append(fileHandles, f)
	}
	err = os.Mkdir(filepath.Join(dir, "testsubdir"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	for _, subfile := range []string{"file3", "file4"} {
		f, err := createRandFile(filepath.Join(dir, subfile), 1024)
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(f.Name())
		fileHandles = append(fileHandles, f)
	}
	s := New(Config{[]string{dir}})
	evs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 4 {
		t.Fatal("wrong number of events, got", len(evs), "wanted 4")
	}
}

// TestSentinel verifies that sentinel generates correct integrity events when
// file changes occur.
func TestSentinel(t *testing.T) {
	// make a few test files
	var files []string
	var fileHandles []*os.File
	var originalChecksums []checksum
	for _, filename := range []string{"file1", "file2", "file3"} {
		f, err := ioutil.TempFile("", filename)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		_, err = io.CopyN(f, rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f.Name())
		fileHandles = append(fileHandles, f)
		checksum, err := checksumFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		originalChecksums = append(originalChecksums, checksum)
	}

	// construct a sentinel and watch those files.
	s := New(Config{files})

	// first scan should result in 3 creation events
	ev, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != len(files) {
		t.Fatal("expected three events")
	}
	for i, e := range ev {
		if e.Evtype != evCreate {
			t.Fatal("expected evCreate initially, got", e.Evtype)
		}
		if e.OrigChecksum != "" {
			t.Fatal("OrigChecksum should be empty on first scan")
		}
		if e.NewChecksum != originalChecksums[i] {
			t.Fatal("incorrect NewChecksum: got ", e.NewChecksum, "wanted", originalChecksums[i])
		}
	}
	// next scan should yield 0 events (there were no changes)
	ev, err = s.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 0 {
		t.Fatal("expected no events, got", len(ev))
	}

	// modify one of the files
	_, err = io.CopyN(fileHandles[0], rand.Reader, 8)
	if err != nil {
		t.Fatal(err)
	}
	// should result in one event
	ev, err = s.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 {
		t.Fatal("expected one event, got", len(ev))
	}
	if ev[0].Evtype != evModify {
		t.Fatal("expected evModify, got ", ev[0].Evtype)
	}
	if ev[0].OrigChecksum != originalChecksums[0] {
		t.Fatal("incorrect original checksum")
	}
	newchecksum, err := checksumFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if ev[0].NewChecksum != newchecksum {
		t.Fatal("incorrect new checksum")
	}
	// subsequent scan should have zero events
	ev, err = s.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 0 {
		t.Fatal("expected zero events, got", len(ev))
	}

	// save the sentinel and reload it, verifying Save/Open function correctly
	err = s.Save("testout", "testpass")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("testout")

	s2, err := Open("testout", "testpass")
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.PriorScans) != len(s.PriorScans) {
		t.Fatal("wrong number of scans after open")
	}
	if len(s2.WatchFiles) != len(s.WatchFiles) {
		t.Fatal("wrong number of watch files after open")
	}
	if len(s2.KnownObjects) != len(s.KnownObjects) {
		t.Fatal("wrong number of known objects after open")
	}

	// PriorScans should have the correct number of scans (four)
	if len(s.PriorScans) != 4 {
		t.Fatal("wrong number of prior scans: ", len(s.PriorScans), " wanted 4")
	}
}
