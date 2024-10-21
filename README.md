# trivy-plugin-source-severity
Template for Trivy plugins


## Installation
```shell
trivy plugin install github.com/datma-health/trivy-plugin-source-severity
```

## Usage

```shell
trivy image --format json --output plugin=source-severity [--output-plugin-arg "--severity=CRTIICAL --severity-sources=ubuntu"] <image_name>
```

OR

```shell
trivy image -f json <image_name> | trivy source-severity [--severity CRITICAL --severity-sources ubuntu]
```

This plugin aims to upgrade severities based on CVSS base score. However, it is not clear if this is what is we want -- the main motivation was to try and match what Azure Defender for Cloud was calling out as high or critical vulnerabilities. Even after adding `--ignore-unfixed` it seems like this approach results in more CVEs than we get from Azure Defender.

## Local testing

Trivy's docs suggest that local testing of the plugin can be done by simply building the executable, creating a tarball (`make tarball`) and then trying to install that (`trivy plugin install <tarball>`). However, in practice, this doesn't seem to work without amending the plugin.yaml file. Specifically, for whatever os/arch combo you're testing this on, change the `uri:` field to point to something like `/tmp/<tarball>` and then copy the tarball to that location. Finally, do a `trivy plugin install /tmp/<tarball>`.