# Changelog

## Meta

This file should adhere to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), but it's manually maintained.  Feel free to comment or make a pull request if something breaks for you.

This project should adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).  Please beat me with a virtual stick if I fail to do so!

## Disclaimer

Quite much of the changelog was AI-generated

## [0.4.0] - [unreleased]

### Added

- Thresholds (`-w`/`-c`) accept the Nagios range format, e.g. `-c 300:` to alert when a document
  newer than 5 minutes is found.  Combined with `--filter`, this alerts on the presence of errors,
  security events and other unwanted documents.  `--min-warning`/`--min-critical` still work

- `--ca-file` to verify the server certificate against a private CA instead of using `-k`
- `-V`/`--version`

- Secondary default netrc location: `/etc/nagios/netrc`
  - Script now automatically tries `~/.netrc` first, then `/etc/nagios/netrc` as fallback
  - No need to specify `--netrc` parameter when using `/etc/nagios/netrc`
  - Improves NRPE/Nagios deployment experience where users lack proper home directories

### Changed

- **BREAKING**: when any threshold option is given, the others no longer default to 3600/7200.
  `-w 300` alone used to imply `-c 7200`
- An age exactly at a maximum threshold is now OK, as the Nagios range format defines it
- Updated help text and README with threshold range examples
  - Simplified credentials setup documentation
  - Consolidated overlapping content between Usage and Examples sections (31% reduction in length)

### Removed

- The unmaintained Bash version `check_opensearch_index.sh`.  It had broken duration formatting,
  swallowed curl errors, and allowed shell command injection through `-w`/`-c`

### Fixed

- Threshold validation now rejects negative values and combinations that can never return OK
  (e.g. `-w 60 -c 600 --min-critical 100`)
- Timestamps are read from the sort value instead of being parsed from the document, which fixes
  dotted field names (`-t event.created`), epoch-millis values, timestamps without a timezone
  and `date_nanos` fields.  Elasticsearch has to be 7.2 or newer; any OpenSearch version works
- Index patterns where some indices lack the timestamp field no longer fail with HTTP 400
- Performance data attaches thresholds to the value they are checked against (`oldest_age` when
  `--count` > 1), includes the `--min-*` thresholds as Nagios ranges
- A trailing slash on `-H` and special characters in `-i` (date math) no longer break the URL
- A timeout while reading the response gives CRITICAL, like a connect timeout
- An unreadable netrc file gives a clear UNKNOWN message
- Invalid command line arguments give UNKNOWN instead of exit code 2, which Nagios reads as CRITICAL

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
- Optimized timestamp parsing to only parse first and last document
  - Significant performance improvement for large `--count` values

### Removed

- Removed unnecessary unique document ID validation
  - OpenSearch already guarantees unique results by document ID
  - Simplified code and reduced unnecessary checks

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
* It may monitor both max and min age of "document number 100".  The minimum age is useful for detecting log flooding.  Flooding log messages typically indicates that something is wrong, and may eat up available disk space very fast.
* In my case, I have an index that is populated by multiple sources, and I need to monitor that one particular source is contributing with a steady stream of logs.  The script accepts a --filter parameter for this.
