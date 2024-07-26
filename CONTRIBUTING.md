# Contribute to the attest Library

Want to hack on the attest library? This guide will help you to find out how to contribute.

This page contains information about reporting issues as well as some tips and guidelines useful to experienced open source contributors. Finally, make sure you read our [community guidelines](#community-guidelines) before you start participating.

## Topics

* [Reporting Security Issues](#reporting-security-issues)
* [Design and Cleanup Proposals](#design-and-cleanup-proposals)
* [Reporting Issues](#reporting-other-issues)
* [Quick Contribution Tips and Guidelines](#quick-contribution-tips-and-guidelines)
* [Community Guidelines](#community-guidelines)

## Reporting security issues

The attest maintainers take security seriously. If you discover a security issue, please bring it to their attention right away!

Please **DO NOT** file a public issue, instead send your report privately to [security@docker.com](mailto:security@docker.com).

Security reports are greatly appreciated and we will publicly thank you for it, although we keep your name confidential if you request it. We also like to send gifts—if you're into schwag, make sure to let us know. We currently do not offer a paid security bounty program, but are not ruling it out in the future.

## Reporting other issues

A great way to contribute to the project is to send a detailed report when you encounter an issue. We always appreciate a well-written, thorough bug report, and will thank you for it!

Check that [our issue database](https://github.com/docker/attest/issues) doesn't already include that problem or suggestion before submitting an issue. If you find a match, you can use the "subscribe" button to get notified on updates. Do *not* leave random "+1" or "I have this too" comments. Those comments can become annoying very quickly. Instead, use [GitHub reactions](https://docs.github.com/en/free-pro-team@latest/github/writing-on-github/using-emojis).

### How to report a bug

* **Use a clear and descriptive title** for the issue to identify the problem.
* **Describe the exact steps which reproduce the problem** in as many details as possible. When listing steps, **don't just say what you did, but explain how you did it**.
* **Provide specific examples to demonstrate the steps**. Include links to files or GitHub projects, or copy/pasteable snippets, which you use in those examples. If you're providing snippets in the issue, use [Markdown code blocks](https://help.github.com/articles/markdown-basics/#multiple-lines).
* **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
* **Explain which behavior you expected to see instead and why.**
* **Include screenshots and animated GIFs** which show you following the described steps and clearly demonstrate the problem.
* **If the problem is related to performance or memory**, include a [CPU profile capture](https://blog.golang.org/profiling-go-programs) with your report.
* **If the problem wasn't triggered by a specific action**, describe what you were doing before the problem happened.
* **Include the version of attest you are using**.
* **Include the name and version of the OS you're using**.

## Quick contribution tips and guidelines

This section gives a brief overview of how to propose a change to attest.

### Contribution flow

1. Fork the repository on GitHub.
2. Create a topic branch from where you want to base your work.
3. Make commits of logical units.
4. Make sure your commit messages are in the proper format (see below).
5. Push your changes to a topic branch in your fork of the repository.
6. Submit a pull request to the original repository.

### Format of the commit message

We follow a rough convention for commit messages borrowed from Angular.

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **style**: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **perf**: A code change that improves performance
- **test**: Adding missing or correcting existing tests
- **chore**: Changes to the build process or auxiliary tools and libraries such as documentation generation

### Code review process

All submissions, including submissions by project members, require review. We use GitHub pull requests for this purpose.

### Tips for contributors

1. All code should be formatted with `gofmt -s`.
2. All code should pass the default levels of [`golint`](https://github.com/golang/lint).
3. All code should follow the guidelines covered in [Effective Go](http://golang.org/doc/effective_go.html) and [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments).
4. Comment the code. Tell us the why, the history, and the context.
5. Document _all_ declarations and methods, even private ones. Declare expectations, caveats, and anything else that may be important. If a type gets exported, having the comments already there will ensure it's ready.
6. Variable name length should be proportional to its context and no longer. `noCommaALongVariableNameLikeThisIsNotMoreClearWhenASimpleCommentWouldDo`. In practice, short methods will have short variable names and globals will have longer names.
7. No underscores in package names. If you need a compound name, step back, and re-examine why you need a compound name. If you still think you need a compound name, lose the underscore.
8. No utils or helpers packages. If a function is not general enough to warrant its own package, it has not been written generally enough to be a part of a util package. Just leave it unexported and well-documented.
9. All tests should run with `go test` and outside tooling should not be required. No, we don't need another unit testing framework. Assertion packages are acceptable if they provide _real_ incremental value.
10. Even though we call these "rules" above, they are actually just guidelines. Since you've read all the rules, you now know that.

If you are having trouble getting into the mood of idiomatic Go, we recommend reading through [Effective Go](https://go.dev/doc/effective_go). The [Go Blog](https://go.dev/blog/) is also a great resource. Drinking the kool-aid is a lot easier than going thirsty.
