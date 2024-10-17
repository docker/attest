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
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
)

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

func Archive(ctx context.Context, gitRepoDir string, gitDir string) io.Reader {
	readPipe, writePipe := io.Pipe()

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

		// execute the command and capture any error
		err = runArchiveCmd(ctx, writePipe, gitRepoDir, gitDir)
	}()

	return readPipe
}

func runArchiveCmd(ctx context.Context, stdout io.Writer, gitRepoDir string, gitDir string) error {
	// set a timeout to avoid the command hanging indefinitely
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	treeish := fmt.Sprintf("HEAD:%s", gitDir)

	cmd := exec.CommandContext(ctx, "git", "archive", "--format=tar", treeish)
	cmd.Dir = gitRepoDir // run the command inside the git repo directory

	// set the standard output to the provided writer
	cmd.Stdout = stdout

	// capture standard error so we can include it in the error message if the command fails
	stderr := new(bytes.Buffer)
	cmd.Stderr = stderr

	// Run the command and check for errors
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			err = &execError{ExitError: ee, stderr: stderr.Bytes()}
		}
		return err
	}

	return nil
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
		// TODO: I think it's fine to ignore the gosec warning here but double-check
		_, err = io.Copy(tw, tr) // #nosec G110
		if err != nil {
			return err
		}
	}
}
