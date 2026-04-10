# CLAUDE.md — mallcop-connectors

> Go library: mallcop connector implementations for 108+ cloud services.
> Scaffolded under work item mallcoppro-eb1.

## Cross-Repo Architecture

See ~/projects/mallcop-pro/CLAUDE.md for full cross-repo architecture, including:
- mallcop-pro tenant service (Forge integration, Polar checkout, donut billing)
- mallcop OSS CLI (connectors, detectors, skills, actors)
- Forge inference proxy (accounts, billing, metering, Bedrock routing)

## This Repo

mallcop-connectors provides connector implementations for cloud service APIs:
- Each connector fetches security-relevant configuration from a single service
- Connectors are consumed by mallcop-skills for analysis
- Target: 108+ connectors across cloud, dev tools, payments, auth, monitoring, security, comms, supply chain

## Related Items

- Parent work item: mallcoppro-eb1
- Connector specs: ~/projects/mallcop-pro/grid/specs/
- mallcop-skills: ~/projects/mallcop-skills
- mallcop-legion: ~/projects/mallcop-legion
