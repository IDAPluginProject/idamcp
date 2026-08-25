# How to contribute

We'd love to accept your patches and contributions to this project!

## Sign our Contributor License Agreement

Contributions to this project must be accompanied by a
[Contributor License Agreement](https://cla.developers.google.com/about) (CLA).
You (or your employer) retain the copyright to your contribution; this simply
gives us permission to use and redistribute your contributions as part of the
project.

If you or your current employer have already signed the Google CLA (even if it
was for a different project), you probably don't need to do it again.

Visit <https://cla.developers.google.com/> to see your current agreements or to
sign a new one.

## Review our community guidelines

This project follows
[Google's Open Source Community Guidelines](https://opensource.google/conduct/).

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.

## Development and Testing Workflow

When contributing code changes, please make sure your changes align with the
project architecture and pass our existing tests:

1.  **Build and Test**: Run `make test` from the root directory to run unit
    tests and ensure your changes do not introduce regressions. If you modify
    core tool definitions or proxy routing, run `make build`.
2.  **Code Style**: Ensure Python code adheres to PEP 8 standards, uses type
    annotations (compatible with Python 3.10+), and includes descriptive
    docstrings.
3.  **Pull Requests**: Open a GitHub Pull Request with a clear summary of what
    your change does and any relevant context or testing steps.
