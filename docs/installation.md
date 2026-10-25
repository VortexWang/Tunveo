# Installing Tunveo

Tunveo currently provides a source-development baseline. Published binaries and container tags are not assumed to exist.

## From source

Install Go 1.26.5, then:

```sh
git clone https://github.com/VortexWang/Tunveo.git
cd Tunveo
go mod download
go mod verify
go build -trimpath -o bin/tunveo ./cmd/tunveo
./bin/tunveo version
```

## Local container build

```sh
docker build --build-arg VERSION=dev -t tunveo:dev .
docker run --rm tunveo:dev version
```

The image includes the root and bundled-library license notices. No upstream installer script is used to install Tunveo.

Read [migration.md](migration.md) before moving existing state. Configuration and command options are documented in [cli.md](cli.md) and [configuration.md](configuration.md).
