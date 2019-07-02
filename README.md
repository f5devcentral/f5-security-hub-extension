# F5 Security Hub Extension

## Introduction

The F5 Security Hub Extension is a BIG-IP iControl LX Extension for posting ASM log events to AWS Security Hub. AWS Security Hub provides a datebase and dashboard for managing security event notifations across an AWS Cloud Deployment.

This extension is community supported.

## Requirements

BIG-IP VE 14.0 or later running on EC2

BIG-IP 13.1 will work but the logging profile must be created by hand see f5devcentral/f5-security-hub-extension#1

## Docs

For installation and usage instructions, see the ./docs folder

## Building

This package works with icrdk, which can be found here: https://github.com/f5devcentral/f5-icontrollx-dev-kit

From the root directory, an invocation to `icrdk build` will place a built RPM inside the `./build` directory.

The package can be deployed like any other iControl LX extension, or upon configuring a local `devconfig.json`, the package can be deployed with `icrdk deploy`
