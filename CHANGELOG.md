# Changelog

## Meta

This file should adhere to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), but it's manually maintained.  Feel free to comment or make a pull request if something breaks for you.

This project should adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).  Please beat me with a virtual stick if I fail to do so!

## Disclaimer

Changelog for 0.2.0, 0.3.0 and 0.4.0 was AI-generated, the rest of this file was written by a human.

## [0.4.0] - [2025-11-21]

### Added

- New `--reverse` mode for alert-on-presence monitoring
  - Inverts check logic: returns OK when no documents found, CRITICAL when documents ARE found
  - Designed for monitoring critical errors, security events, and exceptional conditions
  - Ignores max age thresholds (--warning, --critical) in reverse mode
  - Only uses min-age thresholds (--min-warning, --min-critical) to filter recent events
  - Example use case: Alert CRITICAL if ERROR logs found in last 5 minutes
  - Combines with `--filter` to search for specific message patterns
  - Typical applications:
    - Critical application errors that should never happen
    - Security violations (unauthorized access, failed authentication)
    - System failures (out of memory, disk full, database down)
    - Deployment failures or rollback events

### Changed

- Updated help text with reverse mode examples
- Enhanced README with comprehensive reverse mode documentation
  - New "Reverse Mode" section with use cases and examples
  - Updated Features list to highlight reverse mode capability
  - Added NRPE configuration examples for reverse mode monitoring

## [0.3.0] - [2025-11-20]

### Added

- New `--netrc` parameter to specify custom .netrc file location
  - Solves issues with NRPE/system users that have non-standard home directories
  - Example: `--netrc /etc/nagios/credentials/opensearch.netrc`
  - Default behavior unchanged (still uses `~/.netrc` if not specified)

### Changed

- Enhanced documentation for NRPE deployments
  - Added complete guide for setting up credentials with system users
  - Updated all NRPE examples to show `--netrc` usage
  - Included proper file permissions and ownership instructions

## [0.2.0] - [2025-11-20]

### Changed

- **BREAKING**: Renamed `--min-unique` parameter to `--count` for better clarity
  - The old name was confusing and sounded like a minimum threshold
  - New name clearly indicates "number of documents to check"
  - Update your scripts: `--min-unique 5` → `--count 5`

### Removed

- Removed unnecessary unique document ID validation
  - OpenSearch already guarantees unique results by document ID
  - Simplified code and reduced unnecessary checks

### Fixed

- Optimized timestamp parsing to only parse first and last document
  - Previously parsed all N documents (O(N) complexity)
  - Now only parses 2 documents regardless of `--count` value (O(1) complexity)
  - Significant performance improvement for large `--count` values

### Added

- Security documentation for creating read-only monitoring users
  - Complete instructions for OpenSearch Security Plugin
  - Alternative instructions for Elasticsearch
  - Emphasizes least-privilege access (only `indices:data/read/search` permission needed)

## [0.1.0] - [2025-11-20]

As version 0.1.0 is the first release of the project, there are not much changes as such to report - but I will copy the (human-written) release notes:

Basic features:

* Can give alerts if the recent activity in an OpenSearch index is old.
* Instead of checking the most recent document, it may be configured to look i.e. 100 documents behind and check the age of that document.  This will give a more stable monitoring, may prevent flapping state, useful to monitor that there is a minimum volume of logs coming in.
* It may monitor both max and min age of "document number 100".  The minimum age is useful for detecting log flooding.  Flooding log messages typically indicates that something is wrong, and may eat up avaailable disk space very fast.
* In my case, I have an index that is populated by multiple sources, and I need to monitor that one particular source is contributing with a steady stream of logs.  The script accepts a --filter parameter for this.
