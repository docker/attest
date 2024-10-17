/*
   Copyright 2024 Docker attest authors

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
package useragent

import (
	"context"
	"testing"
)

// test the user agent setting and getting.
func TestSetUserAgent(t *testing.T) {
	ctx := context.Background()
	if Get(ctx) != defaultUserAgent {
		t.Errorf("expected user agent to be '%s', got %q", defaultUserAgent, Get(ctx))
	}

	ctx = Set(ctx, "test-agent")
	if Get(ctx) != "test-agent" {
		t.Errorf("expected user agent to be 'test-agent', got %q", Get(ctx))
	}
}
