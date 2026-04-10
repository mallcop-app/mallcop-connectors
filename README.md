# mallcop-connectors

Go library — mallcop connector implementations for 108+ cloud services. Each connector fetches security-relevant data from a single service API.

## Overview

mallcop-connectors provides a unified interface for fetching security-relevant configuration and audit data from cloud services, developer tools, payment systems, auth providers, and more.

## Architecture

```
mallcop-skills
  → mallcop-connectors (this repo)
    → Service APIs (AWS, GCP, Azure, GitHub, Stripe, ...)
```

Each connector:
1. Authenticates with its target service API
2. Fetches security-relevant configuration data
3. Returns structured data for analysis by mallcop-skills

## Related

- Cross-repo architecture: ~/projects/mallcop-pro/CLAUDE.md
- Parent work item: mallcoppro-eb1
- mallcop OSS: https://github.com/thirdiv/mallcop
- mallcop-skills: https://github.com/thirdiv/mallcop-skills
- mallcop-legion: https://github.com/thirdiv/mallcop-legion

## License

MIT — Copyright (c) 2026 Third Division Labs
