# ghp migrate

Run database migrations.

    ghp migrate [--config path/to/config.yaml]

## Description

Applies any pending database schema migrations. Run this before starting the
server for the first time and after upgrading to a new version.

## Subcommands

### ghp migrate status

Check migration status without applying changes:

    ghp migrate status

Outputs each migration and whether it has been applied.

## Examples

    ghp migrate --config /etc/ghp/server.yaml
    ghp migrate status
