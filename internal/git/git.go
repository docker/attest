/*
   Copyright Docker attest authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package git

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
)

// GitCommand is the path to the git binary, overridden in tests to check behavior when git is not installed.
var GitCommand = "git"

func Clone(ctx context.Context, gitRepo string, gitCommit string, targetDir string) error {
	const localBranch = "FETCH_HEAD"

	repo, err := git.PlainInit(targetDir, false)
	if err != nil {
		return fmt.Errorf("failed to init: %w", err)
	}

	remote, err := repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{gitRepo},
		Fetch: []config.RefSpec{
			config.RefSpec(fmt.Sprintf("%s:%s", gitCommit, localBranch)),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to add remote: %w", err)
	}

	err = remote.FetchContext(ctx, &git.FetchOptions{
		Depth: 1,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch: %w", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}
	err = wt.Checkout(&git.CheckoutOptions{
		Branch: plumbing.ReferenceName(localBranch),
	})
	if err != nil {
		return fmt.Errorf("failed to checkout: %w", err)
	}

	return nil
}

type execError struct {
	*exec.ExitError
	stderr []byte
}

func (e *execError) Error() string {
	trimmed := bytes.TrimSpace(e.stderr)
	if len(trimmed) == 0 {
		return e.ExitError.Error()
	}
	return fmt.Sprintf("%s, %q", e.ExitError.Error(), string(bytes.TrimSpace(e.stderr)))
}

func (e *execError) Unwrap() error {
	return e.ExitError
}

// Archive creates a tar archive of the files in the subdirectory given by subdir of the git repository at gitRepoDir.
// This is accomplished by running `git archive --format=tar HEAD:subdir` in the git repository directory.
//
// The archive is written to the returned io.Reader. It is not necessary to close the returned reader.
// Any error encountered while starting the command will be returned immediately.
// Any error encountered after the command is running will be returned on the next read from the returned io.Reader.
func Archive(ctx context.Context, gitRepoDir string, subdir string) (io.Reader, error) {
	readPipe, writePipe := io.Pipe()

	treeish := fmt.Sprintf("HEAD:%s", subdir)
	cmd := exec.CommandContext(ctx, GitCommand, "archive", "--format=tar", treeish)
	// run the command inside the git repo directory
	cmd.Dir = gitRepoDir

	// set the standard output to the write end of the pipe
	cmd.Stdout = writePipe

	// capture standard error so we can include it in the error message if the command fails
	stderr := new(bytes.Buffer)
	cmd.Stderr = stderr

	err := cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	// spawn a goroutine to wait for the command to finish and close the write pipe
	go func() {
		var err error // variable to hold any error

		defer func() {
			if p := recover(); p != nil {
				// if we panic, set err to a new error wrapping the panic value
				err = fmt.Errorf("panic: %v", p)
			}

			// send any error from the command (or the panic above) to the write pipe
			// or nil if there was no error
			// this will cause the error to be returned on the next read from the read pipe
			writePipe.CloseWithError(err)
		}()

		// wait for the command to finish and capture any error
		err = cmd.Wait()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				err = &execError{ExitError: ee, stderr: stderr.Bytes()}
			}
		}
	}()

	return readPipe, nil
}

func TarScrub(in io.Reader, out io.Writer) error {
	tr := tar.NewReader(in)
	tw := tar.NewWriter(out)
	defer tw.Flush() // note: flush instead of close to avoid the empty block at EOF

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		newHdr := &tar.Header{
			Typeflag: hdr.Typeflag,
			Name:     hdr.Name,
			Linkname: hdr.Linkname,
			Size:     hdr.Size,
			Mode:     hdr.Mode,
			Devmajor: hdr.Devmajor,
			Devminor: hdr.Devminor,
		}
		if err := tw.WriteHeader(newHdr); err != nil {
			return err
		}
		_, err = io.CopyN(tw, tr, hdr.Size)
		if err != nil {
			return err
		}
	}
}
