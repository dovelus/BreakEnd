# NOTE:
> [!WARNING]
> Rewrite in progress i found some edge cases where files hash doesn't match with the original ones.

## Requiremets:

The builder needs to be run inside windows

    1. GO - 1.25.x

    2. Garble (https://github.com/burrowers/garble)
        Install:  go install mvdan.cc/garble@latest

## Usage:

    1. Compile the builder
        go build .

    2. Execute the builder
        .\breakend-builder.exe

    3. Copy the 2 executables that are inside the "release" to a safe location
