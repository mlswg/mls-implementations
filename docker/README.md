Docker Interop Tooling
======================

This directory contains docker files to facilitate interop testing among
different stacks.  There is a Dockerfile for each implementation, and one for
the test runner script.  The `docker-compose.yml` file connects the
implementation with the test runner and runs a test config.  You can edit the
docker-compose file to plug in different implementations or run different test
configs.

## Running tests

```
# Run the tests (after building the containers if necessary)
> docker-compose up
```

The first run will take several minutes, as Docker sets up the containers and
builds the implementations.  After that, running the compose script should only
take as long as it takes to run the tests.  You may have to manually kill the
compose script (`Ctrl-C`), since the implementation containers will keep running
until killed.

## Adding an implementation

If you want to add your stack to this testing scheme, please submit a PR that
does the following:

* Add a Dockerfile named `Dockerfile.<name>` that clones your repo, builds the
  implementation, and starts the interop harness.

* Add a service to `docker-compose.yml` to run your implementation.
