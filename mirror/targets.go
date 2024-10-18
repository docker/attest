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

package mirror

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/docker/attest/oci"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// GetTUFTargetMirrors returns a list of top-level target files as MirrorImages (image with tag).
func (m *TUFMirror) GetTUFTargetMirrors() ([]*Image, error) {
	targetMirrors := []*Image{}
	md := m.TUFClient.GetMetadata()

	// for each top-level target file, create an image with the target file as a layer
	targets := md.Targets[metadata.TARGETS].Signed.Targets
	for _, t := range targets {
		// download target file
		file, err := m.TUFClient.DownloadTarget(t.Path, filepath.Join(m.tufPath, "download"))
		if err != nil {
			return nil, fmt.Errorf("failed to download target %s: %w", t.Path, err)
		}
		// create image with target file as layer
		img := empty.Image
		img = mutate.MediaType(img, types.OCIManifestSchema1)
		img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
		// annotate layer
		hash, ok := t.Hashes["sha256"]
		if !ok {
			return nil, fmt.Errorf("missing sha256 hash for target %s", t.Path)
		}
		name := hash.String() + "." + t.Path
		ann := map[string]string{tufFileAnnotation: name}
		layer := mutate.Addendum{Layer: static.NewLayer(file.Data, tufTargetMediaType), Annotations: ann}
		img, err = mutate.Append(img, layer)
		if err != nil {
			return nil, fmt.Errorf("failed to append role layer to image: %w", err)
		}
		targetMirrors = append(targetMirrors, &Image{Image: &oci.EmptyConfigImage{Image: img}, Tag: name})
	}
	return targetMirrors, nil
}

// GetDelegatedTargetMirrors returns a list of delegated target files as MirrorIndexes (image index with tag)
// each image in the index contains a delegated target file.
func (m *TUFMirror) GetDelegatedTargetMirrors() ([]*Index, error) {
	mirror := []*Index{}
	md := m.TUFClient.GetMetadata()

	// for each delegated role, create an image index with target files as images
	roles := md.Targets[metadata.TARGETS].Signed.Delegations.Roles
	for _, role := range roles {
		// create an image index
		index := v1.ImageIndex(empty.Index)

		// get delegated targets metadata for role
		roleMeta, err := m.TUFClient.LoadDelegatedTargets(role.Name, metadata.TARGETS)
		if err != nil {
			return nil, fmt.Errorf("failed to load delegated targets metadata: %w", err)
		}

		// for each target file, create an image with the target file as a layer
		for _, target := range roleMeta.Signed.Targets {
			// download target file
			file, err := m.TUFClient.DownloadTarget(target.Path, filepath.Join(m.tufPath, "download"))
			if err != nil {
				return nil, fmt.Errorf("failed to download target %s: %w", target.Path, err)
			}
			// create image with target file as layer
			img := empty.Image
			img = mutate.MediaType(img, types.OCIManifestSchema1)
			img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
			// annotate layer
			hash, ok := target.Hashes["sha256"]
			if !ok {
				return nil, fmt.Errorf("missing sha256 hash for target %s", target.Path)
			}
			filename := filepath.Base(target.Path)
			subdir, ok := strings.CutSuffix(target.Path, "/"+filename)
			if !ok {
				return nil, fmt.Errorf("failed to find target subdirectory [%s] in path: %s", subdir, target.Path)
			}
			name := hash.String() + "." + filename
			ann := map[string]string{tufFileAnnotation: name}
			layer := mutate.Addendum{Layer: static.NewLayer(file.Data, tufTargetMediaType), Annotations: ann}
			img, err = mutate.Append(img, layer)
			if err != nil {
				return nil, fmt.Errorf("failed to append role layer to image: %w", err)
			}
			emptyConfigImage := &oci.EmptyConfigImage{Image: img}
			// append image to index with annotation
			index = mutate.AppendManifests(index, mutate.IndexAddendum{
				Add: emptyConfigImage,
				Descriptor: v1.Descriptor{
					Annotations: map[string]string{
						tufFileAnnotation: fmt.Sprintf("%s/%s", subdir, name),
					},
				},
			})
		}
		mirror = append(mirror, &Index{Index: index, Tag: role.Name})
	}
	return mirror, nil
}
