# Preface

This library is an open source project and contributions are welcome!

Just make sure to respect the [Code of Conduct](CODE_OF_CONDUCT.md).


# Tests

**All functionalities should have automated testing.**

As this is inherently a networked crate, most tests require an LDAP server
(with particular content) to run against. The CI-pipeline will take care of online,
but you can do it locally too with podman or docker.


## Running integration tests locally

Make sure that your container runtime has read access to the files in `data` directory.

### docker-compose

```commandline
$ docker-compose --file docker-compose.yml --detach up
$ cargo test
$ docker-compose --file docker-compose.yml down
```

### podman

```commandline
$ podman-compose --file docker-compose.yml --detach up
$ cargo test
$ podman-compose --file docker-compose.yml down
```

You can also drop the `--detach` option to see the LDAP server output,
but in this case you will need to run the tests from another terminal.
