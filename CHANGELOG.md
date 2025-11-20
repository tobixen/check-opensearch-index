# Changelog

## Meta

This file should adhere to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), but it's manually maintained.  Feel free to comment or make a pull request if something breaks for you.

This project should adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).  Please beat me with a virtual stick if I fail to do so!

## Disclaimer

As of release 0.1.0, this file was 100% written by a human.

## [0.1.0] - [2025-11-20]

As version 0.1.0 is the first release of the project, there are not much changes as such to report - but I will copy the (human-written) release notes:

Basic features:

* Can give alerts if the recent activity in an OpenSearch index is old.
* Instead of checking the most recent document, it may be configured to look i.e. 100 documents behind and check the age of that document.  This will give a more stable monitoring, may prevent flapping state, useful to monitor that there is a minimum volume of logs coming in.
* It may monitor both max and min age of "document number 100".  The minimum age is useful for detecting log flooding.  Flooding log messages typically indicates that something is wrong, and may eat up avaailable disk space very fast.
* In my case, I have an index that is populated by multiple sources, and I need to monitor that one particular source is contributing with a steady stream of logs.  The script accepts a --filter parameter for this.
