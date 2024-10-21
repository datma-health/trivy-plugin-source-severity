# trivy-plugin-ubuntu-severity
Template for Trivy plugins


## Installation
```shell
trivy plugin install github.com/mlathara/trivy-plugin-ubuntu-severity
```

## Usage

```shell
trivy image --format json --output plugin=ubuntu-severity [--output-plugin-arg "--severity=CRTIICAL --severity-sources=ubuntu"] <image_name>
```

OR

```shell
trivy image -f json <image_name> | trivy ubuntu-severity [--severity CRITICAL --severity-sources ubuntu]
```

This plugin aims to upgrade severities based on CVSS base score. However, it is not clear if this is what is we want -- the main motivation was to try and match what Azure Defender for Cloud was calling out as high or critical vulnerabilities. Even after adding `--ignore-unfixed` it seems like this approach results in more CVEs than we get from Azure Defender.